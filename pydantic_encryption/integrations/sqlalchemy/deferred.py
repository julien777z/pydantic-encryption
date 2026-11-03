from collections import defaultdict
from collections.abc import Iterable
from functools import partial
from types import FunctionType
from typing import Final, Self, cast
from weakref import WeakSet

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import ColumnDefault, Connection, event, select
from sqlalchemy.orm import Mapper, QueryContext
from sqlalchemy.orm.attributes import get_history, instance_state

from pydantic_encryption.integrations.sqlalchemy.bulk import bulk_decrypt_entities
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    MappedT,
    read_raw_cell,
    require_row_key_columns,
    row_key_segment,
)
from pydantic_encryption.serialization import decode_value, require_encryptable
from pydantic_encryption.types import EncryptedValue

ZERO_ARGUMENT_DEFAULT_CODES: Final = frozenset(
    cast(FunctionType, ColumnDefault(default).arg).__code__
    for default in (lambda: None, partial(lambda: None))
)


def install_descriptors(mapper: Mapper[MappedT], class_: type[MappedT]) -> None:
    """Mark encrypted columns deferred and wrap their class attrs with the on-access descriptor."""

    if row_bound_columns(mapper):
        require_row_key_columns(mapper)

    for attribute, column in mapper.columns.items():
        if not isinstance(column.type, SQLAlchemyEncryptedValue):
            continue

        if not column.type.deferred:
            column.type = column.type.copy()
            column.type.deferred = True

        if isinstance(class_.__dict__.get(attribute), DecryptOnAccessDescriptor):
            continue

        setattr(class_, attribute, DecryptOnAccessDescriptor(getattr(class_, attribute), class_, attribute))


def row_bound_columns(mapper: Mapper[MappedT]) -> list[tuple[str, SQLAlchemyEncryptedValue]]:
    """Return the attribute and type of every column on a mapping that binds each row separately."""

    return [
        (mapper.get_property_by_column(column).key, column.type)
        for column in mapper.columns
        if isinstance(column.type, SQLAlchemyEncryptedValue) and column.type.row_bound
    ]


def assign_client_side_primary_key(mapper: Mapper[MappedT], target: MappedT) -> None:
    """Apply a primary key's zero-argument client-side default early, so a row-bound cell can name its row."""

    for column in mapper.primary_key:
        attribute = mapper.get_property_by_column(column).key
        if getattr(target, attribute, None) is not None:
            continue

        default = column.default
        if default is None or default.is_sequence or default.is_clause_element:
            continue

        if not default.is_callable:
            setattr(target, attribute, default.arg)

            continue

        if getattr(default.arg, "__code__", None) in ZERO_ARGUMENT_DEFAULT_CODES:
            setattr(target, attribute, default.arg(None))


def replaced_row_key(mapper: Mapper[MappedT], target: MappedT) -> list[object] | None:
    """Return the key values a row is moving away from, or ``None`` where it keeps the ones it had."""

    replaced: list[object] = []
    moved = False
    for column in mapper.primary_key:
        attribute = mapper.get_property_by_column(column).key
        history = get_history(target, attribute)

        if history.deleted:
            replaced.append(history.deleted[0])
            moved = True
        else:
            replaced.append(getattr(target, attribute))

    return replaced if moved else None


def read_stored_cell(
    connection: Connection, mapper: Mapper[MappedT], attribute: str, row_key_values: list[object]
) -> object:
    """Read a cell the row's ORM state has not loaded from the stored row its key values name."""

    statement = (
        select(mapper.columns[attribute])
        .select_from(mapper.persist_selectable)
        .where(*(column == value for column, value in zip(mapper.primary_key, row_key_values)))
    )

    return connection.execute(statement).scalar_one_or_none()


def seal_row_bound_cells(
    mapper: Mapper[MappedT], connection: Connection, target: MappedT, *, updating: bool
) -> None:
    """Seal row-bound cells under the context naming their row, or only those an update changes."""

    columns = row_bound_columns(mapper)

    if not columns:
        return

    assign_client_side_primary_key(mapper, target)
    replaced_values = replaced_row_key(mapper, target) if updating else None
    replaced_key = (
        [row_key_segment(column, value) for column, value in zip(mapper.primary_key, replaced_values)]
        if replaced_values is not None
        else None
    )
    unloaded = instance_state(target).unloaded

    for attribute, column_type in columns:
        if replaced_values is not None and attribute in unloaded:
            value = read_stored_cell(connection, mapper, attribute, replaced_values)
        else:
            value = read_raw_cell(target, attribute)

        if value is None:
            continue

        if isinstance(value, EncryptedValue):
            if replaced_key is None:
                continue

            plaintext = decode_value(
                column_type.decrypt_cell(value, context=column_type.cell_context(*replaced_key))
            )
        elif updating and replaced_key is None and not get_history(target, attribute).added:
            continue
        else:
            plaintext = require_encryptable(value)

        setattr(
            target, attribute, column_type.encrypt_cell(plaintext, context=column_type.context_for(target))
        )


def encrypt_row_bound_cells(mapper: Mapper[MappedT], connection: Connection, target: MappedT) -> None:
    """Seal every row-bound cell of a row being inserted under the context naming its row."""

    seal_row_bound_cells(mapper, connection, target, updating=False)


def reencrypt_changed_row_bound_cells(
    mapper: Mapper[MappedT], connection: Connection, target: MappedT
) -> None:
    """Seal the row-bound cells an update assigns, or every one where the row's primary key moves."""

    seal_row_bound_cells(mapper, connection, target, updating=True)


def on_orm_load(instance: object, context: QueryContext | None) -> None:
    """Add a freshly loaded instance to the session's pending-decrypt bucket."""

    if context is None:
        return

    bucket: dict[type[object], WeakSet[object]] = context.session.info.setdefault(
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
        event.listen(cls, "before_update", reencrypt_changed_row_bound_cells)

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
    "reencrypt_changed_row_bound_cells",
]
