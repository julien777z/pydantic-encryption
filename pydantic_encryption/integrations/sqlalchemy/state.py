import uuid
from collections.abc import Iterable
from typing import Any, Final, TypeVar
from weakref import WeakSet

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import CHAR, NCHAR, ColumnElement, Enum, Integer, String, Uuid
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Mapper, Session
from sqlalchemy.orm.attributes import instance_state, set_committed_value
from sqlalchemy.types import TypeEngine

from pydantic_encryption.serialization import EncryptableValue

PENDING_DECRYPT_KEY: Final[str] = "__pydantic_encryption_pending_decrypt__"

MappedT = TypeVar("MappedT")


def read_raw_cell(row: object, column_key: str) -> object:
    """Read a column's stored value from ORM state, bypassing attribute descriptors."""

    state = sa_inspect(row, raiseerr=False)

    if state is not None and hasattr(state, "dict"):
        return state.dict.get(column_key)

    return getattr(row, column_key, None)


def set_decrypted(row: object, column_key: str, plaintext: EncryptableValue) -> None:
    """Commit a decrypted value on a row without marking it dirty for the next flush."""

    set_committed_value(row, column_key, plaintext)


def names_row_key(column_type: TypeEngine[object]) -> bool:
    """Return whether a primary key of this type reads back in the form it was written in."""

    if isinstance(column_type, Integer | Uuid):
        return True

    return isinstance(column_type, String) and not isinstance(column_type, CHAR | NCHAR | Enum)


def require_row_key_columns(mapper: Mapper[MappedT]) -> None:
    """Refuse a primary key whose values could read back in another form than the one written."""

    for column in mapper.primary_key:
        if not names_row_key(column.type):
            raise ValueError(
                f"Column {column.table.fullname}.{column.name} is a primary key of type {column.type!r}, "
                f"which a row-bound cell of {mapper.class_.__name__} cannot name its row by: a value of "
                "that type can read back in another form than the one written. Give the table an "
                "integer, UUID, String or Text primary key."
            )


def row_key_segment(column: ColumnElement[Any], value: object) -> str:
    """Return one primary key value in the canonical form its column type reads back as."""

    if isinstance(column.type, Integer):
        return str(int(str(value)))

    if isinstance(column.type, Uuid):
        return str(value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)))

    if not isinstance(value, str):
        raise TypeError(f"Primary key {column.key} holds type {type(value).__name__!r}, not str.")

    return value


def row_key(mapper: Mapper[MappedT], instance: MappedT) -> list[str]:
    """Return the primary key values identifying one row, one canonical context segment each."""

    values: list[str] = []

    for column in mapper.primary_key:
        value = getattr(instance, mapper.get_property_by_column(column).key, None)

        if value is None:
            raise ValueError(
                f"Row of {mapper.class_.__name__} has no {column.key} yet, so its cells cannot bind "
                "to the row they belong to. A row-bound column needs a primary key its application "
                "assigns, or one with a zero-argument client-side default; a server-generated key, or "
                "one whose default reads the insert, does not exist until the insert it would have to "
                "be written into."
            )

        values.append(row_key_segment(column, value))

    return values


def sealed_row_key(mapper: Mapper[MappedT], instance: MappedT) -> list[str]:
    """Return the key a row's stored cells are sealed under: its persisted identity, else its assigned key."""

    identity = instance_state(instance).identity

    if identity is None:
        return row_key(mapper, instance)

    return [row_key_segment(column, value) for column, value in zip(mapper.primary_key, identity)]


def pending_siblings(session: Session, cls: type[object]) -> list[object]:
    """Return pending-decrypt instances of ``cls`` bucketed in ``session`` that it still holds."""

    bucket: dict[type[object], WeakSet[object]] = session.info.get(PENDING_DECRYPT_KEY) or {}

    return [row for row in bucket.get(cls) or () if row in session]


def drop_pending(session: Session, cls: type[object], rows: Iterable[object]) -> None:
    """Remove rows from the pending-decrypt instances of ``cls`` bucketed in ``session``."""

    bucket: dict[type[object], WeakSet[object]] = session.info.get(PENDING_DECRYPT_KEY) or {}
    pending = bucket.get(cls)

    if pending is not None:
        pending.difference_update(rows)


__all__ = [
    "PENDING_DECRYPT_KEY",
    "drop_pending",
    "names_row_key",
    "pending_siblings",
    "read_raw_cell",
    "require_row_key_columns",
    "row_key",
    "row_key_segment",
    "sealed_row_key",
    "set_decrypted",
]
