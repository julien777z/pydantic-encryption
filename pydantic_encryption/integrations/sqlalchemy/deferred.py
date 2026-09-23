from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Self
from weakref import WeakSet

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import event
from sqlalchemy.orm.attributes import get_history

from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY, read_raw_cell, row_key
from pydantic_encryption.integrations.sqlalchemy.bulk import bulk_decrypt_entities
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    ContextBoundType,
    SQLAlchemyEncryptedValue,
)
from pydantic_encryption.serialization import decode_value
from pydantic_encryption.types import EncryptedValue


def install_descriptors(mapper: Any, class_: type) -> None:
    """Mark encrypted columns deferred and wrap their class attrs with the on-access descriptor."""

    for column in mapper.columns:
        if not isinstance(column.type, SQLAlchemyEncryptedValue):
            continue

        if not column.type._deferred:
            column.type = column.type.copy()
            column.type._deferred = True

        column_key = column.key
        existing = class_.__dict__.get(column_key)
        if isinstance(existing, DecryptOnAccessDescriptor):
            continue

        wrapped = getattr(class_, column_key, None)
        if wrapped is None:
            continue

        try:
            setattr(class_, column_key, DecryptOnAccessDescriptor(wrapped, class_, column_key))
        except (AttributeError, TypeError):
            continue


def row_bound_columns(mapper: Any) -> list[Any]:
    """Return the mapper's columns that bind each row's ciphertext separately."""

    return [
        column
        for column in mapper.columns
        if isinstance(column.type, ContextBoundType) and column.type.row_bound
    ]


def assign_client_side_primary_key(mapper: Any, target: Any) -> None:
    """Apply a primary key's client-side default early, so a row-bound cell can name its row."""

    for column in mapper.primary_key:
        attribute = mapper.get_property_by_column(column).key
        if getattr(target, attribute, None) is not None:
            continue

        default = column.default
        if default is None or default.is_sequence:
            continue

        if default.is_clause_element:
            raise ValueError(
                f"Primary key {mapper.class_.__name__}.{column.key} defaults to a SQL expression the "
                "database evaluates, so its value does not exist until after the insert a row-bound "
                "cell would have to name. Assign the key in the application, or default it to a "
                "Python value or callable."
            )

        setattr(target, attribute, default.arg(None) if default.is_callable else default.arg)


def replaced_row_key(mapper: Any, target: Any) -> list[str] | None:
    """Return the primary key a row is moving away from, or ``None`` where it keeps the one it had."""

    replaced: list[str] = []
    moved = False
    for column in mapper.primary_key:
        attribute = mapper.get_property_by_column(column).key
        history = get_history(target, attribute)
        if history.deleted:
            replaced.append(str(history.deleted[0]))
            moved = True
        else:
            replaced.append(str(getattr(target, attribute)))

    return replaced if moved else None


def encrypt_row_bound_cells(mapper: Any, connection: Any, target: Any) -> None:
    """Seal every row-bound cell on an instance under the context naming its row."""

    columns = row_bound_columns(mapper)
    if not columns:
        return

    assign_client_side_primary_key(mapper, target)
    cell_key = row_key(mapper, target)
    replaced_key = replaced_row_key(mapper, target)

    for column in columns:
        attribute = mapper.get_property_by_column(column).key
        value = read_raw_cell(target, attribute)
        if value is None:
            continue

        if isinstance(value, EncryptedValue):
            if replaced_key is None:
                continue

            value = decode_value(
                column.type.decrypt_cell(value, context=column.type.cell_context(*replaced_key))
            )

        setattr(
            target,
            attribute,
            column.type.encrypt_cell(value, context=column.type.cell_context(*cell_key)),
        )


def on_orm_load(instance: Any, context: Any) -> None:
    """Add a freshly loaded instance to the session's pending-decrypt bucket."""

    if context is None:
        return

    session = context.session
    if session is None:
        return

    bucket: dict[type, WeakSet] = session.info.setdefault(PENDING_DECRYPT_KEY, defaultdict(WeakSet))
    bucket[type(instance)].add(instance)


def on_orm_refresh(instance: Any, context: Any, attrs: Any) -> None:
    """Re-add a refreshed instance to the session's pending-decrypt bucket."""

    on_orm_load(instance, context)


class DeferredDecryptMixin:
    """Defer encrypted-column decryption until first attribute access, batched per column."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", install_descriptors)
        event.listen(cls, "load", on_orm_load)
        event.listen(cls, "refresh", on_orm_refresh)
        event.listen(cls, "before_insert", encrypt_row_bound_cells)
        event.listen(cls, "before_update", encrypt_row_bound_cells)

    async def decrypt(self) -> Self:
        """Decrypt every deferred encrypted column on this instance and loaded relationships."""

        await bulk_decrypt_entities(self)

        return self

    @classmethod
    async def decrypt_many(cls, entities: Any | Iterable[Any] | None) -> None:
        """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

        await bulk_decrypt_entities(entities)


__all__ = [
    "DeferredDecryptMixin",
    "encrypt_row_bound_cells",
    "install_descriptors",
    "on_orm_load",
    "on_orm_refresh",
]
