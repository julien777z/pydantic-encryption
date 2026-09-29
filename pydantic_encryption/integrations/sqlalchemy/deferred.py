from collections import defaultdict
from collections.abc import Iterable
from typing import Self
from weakref import WeakSet

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import Connection, event
from sqlalchemy.orm import Mapper, QueryContext
from sqlalchemy.orm.attributes import get_history

from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    MappedT,
    read_raw_cell,
    row_key,
)
from pydantic_encryption.integrations.sqlalchemy.bulk import bulk_decrypt_entities
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.serialization import decode_value
from pydantic_encryption.types import EncryptedValue


def install_descriptors(mapper: Mapper[MappedT], class_: type[MappedT]) -> None:
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


def assign_client_side_primary_key(mapper: Mapper[MappedT], target: MappedT) -> None:
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


def replaced_row_key(mapper: Mapper[MappedT], target: MappedT) -> list[str] | None:
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


def encrypt_row_bound_cells(mapper: Mapper[MappedT], connection: Connection, target: MappedT) -> None:
    """Seal every row-bound cell on an instance under the context naming its row."""

    columns = [
        (mapper.get_property_by_column(column).key, column.type)
        for column in mapper.columns
        if isinstance(column.type, SQLAlchemyEncryptedValue) and column.type.row_bound
    ]

    if not columns:
        return

    assign_client_side_primary_key(mapper, target)
    cell_key = row_key(mapper, target)
    replaced_key = replaced_row_key(mapper, target)

    for attribute, column_type in columns:
        value = read_raw_cell(target, attribute)
        if value is None:
            continue

        if isinstance(value, EncryptedValue):
            if replaced_key is None:
                continue

            value = decode_value(
                column_type.decrypt_cell(value, context=column_type.cell_context(*replaced_key))
            )

        setattr(
            target,
            attribute,
            column_type.encrypt_cell(value, context=column_type.cell_context(*cell_key)),
        )


def on_orm_load(instance: object, context: QueryContext | None) -> None:
    """Add a freshly loaded instance to the session's pending-decrypt bucket."""

    if context is None:
        return

    session = context.session
    if session is None:
        return

    bucket: dict[type[object], WeakSet[object]] = session.info.setdefault(
        PENDING_DECRYPT_KEY, defaultdict(WeakSet)
    )
    bucket[type(instance)].add(instance)


def on_orm_refresh(instance: object, context: QueryContext | None, attrs: Iterable[str] | None) -> None:
    """Re-add a refreshed instance to the session's pending-decrypt bucket."""

    on_orm_load(instance, context)


class DeferredDecryptMixin:
    """Defer encrypted-column decryption until first attribute access, batched per column."""

    def __init_subclass__(cls, **kwargs: object) -> None:
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
    async def decrypt_many(cls, entities: object | Iterable[object] | None) -> None:
        """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

        await bulk_decrypt_entities(entities)


__all__ = [
    "DeferredDecryptMixin",
    "encrypt_row_bound_cells",
    "install_descriptors",
    "on_orm_load",
    "on_orm_refresh",
]
