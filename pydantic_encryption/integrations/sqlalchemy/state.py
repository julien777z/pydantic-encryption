import re
import uuid
from collections.abc import Iterable, Mapping
from typing import Final, TypeVar
from weakref import WeakSet

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import CHAR, NCHAR, ColumnElement, Enum, Integer, String, Table, Uuid
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Mapper, Session
from sqlalchemy.orm.attributes import instance_state, set_committed_value
from sqlalchemy.types import TypeEngine

from pydantic_encryption.serialization import EncryptableValue

PENDING_DECRYPT_KEY: Final[str] = "__pydantic_encryption_pending_decrypt__"
CANONICAL_INTEGER_PATTERN: Final[re.Pattern[str]] = re.compile(r"0|-?[1-9][0-9]*")

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


def stores_uuid_as_text(column_type: TypeEngine[object], dialect: Dialect | None) -> bool:
    """Return whether a UUID column of this type is stored as text, on ``dialect`` where one is given."""

    if not isinstance(column_type, Uuid):
        return False

    return not column_type.native_uuid or (dialect is not None and not dialect.supports_native_uuid)


def require_row_key_columns(
    columns: Iterable[ColumnElement[object]], name: str, dialect: Dialect | None
) -> None:
    """Refuse a primary key whose values could read back in another form than the one written."""

    for column in columns:
        if stores_uuid_as_text(column.type, dialect):
            raise ValueError(
                f"Column {column.table.fullname}.{column.name} is a UUID primary key stored as text, "
                f"which a row-bound cell of {name} cannot name its row by: text in "
                "more than one spelling reads back as the same UUID. Store the key in a native UUID "
                "column, or give the table an integer, String or Text primary key."
            )

        if not names_row_key(column.type):
            raise ValueError(
                f"Column {column.table.fullname}.{column.name} is a primary key of type {column.type!r}, "
                f"which a row-bound cell of {name} cannot name its row by: a value of "
                "that type can read back in another form than the one written. Give the table an "
                "integer, UUID, String or Text primary key."
            )


def row_key_segment(column: ColumnElement[object], value: object) -> str:
    """Return one primary key value in the canonical form its column type reads back as."""

    if isinstance(column.type, Integer):
        if isinstance(value, int) and not isinstance(value, bool):
            return int.__repr__(value)

        if isinstance(value, str) and (canonical := CANONICAL_INTEGER_PATTERN.fullmatch(value)):
            return canonical.group()

        raise ValueError(
            f"Primary key {column.key} holds a {type(value).__name__} that is not an integer, "
            "nor its canonical decimal form, so it cannot name a row."
        )

    if isinstance(column.type, Uuid):
        return str(value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)))

    if not isinstance(value, str):
        raise TypeError(f"Primary key {column.key} holds type {type(value).__name__!r}, not str.")

    return value


def named_row_key_segment(name: str, column: ColumnElement[object], value: object) -> str:
    """Return one primary key value's segment, refusing a row that has no such value yet."""

    if value is None:
        raise ValueError(
            f"Row of {name} has no {column.key} yet, so its cells cannot bind "
            "to the row they belong to. A row-bound column needs a primary key its application "
            "assigns, or one with a zero-argument client-side default; a server-generated key, or "
            "one whose default reads the insert, does not exist until the insert it would have to "
            "be written into."
        )

    return row_key_segment(column, value)


def row_key(mapper: Mapper[MappedT], instance: MappedT) -> list[str]:
    """Return the primary key values identifying one row, one canonical context segment each."""

    return [
        named_row_key_segment(
            mapper.class_.__name__,
            column,
            getattr(instance, mapper.get_property_by_column(column).key, None),
        )
        for column in mapper.primary_key
    ]


def table_row_key(table: Table, key_values: Mapping[str, object], dialect: Dialect) -> list[str]:
    """Return a table row's key on ``dialect``, one canonical segment per column of the table's own primary key."""

    columns = list(table.primary_key.columns)

    require_row_key_columns(columns, table.fullname, dialect)

    return [named_row_key_segment(table.fullname, column, key_values.get(column.key)) for column in columns]


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


__all__ = [
    "PENDING_DECRYPT_KEY",
    "names_row_key",
    "pending_siblings",
    "read_raw_cell",
    "require_row_key_columns",
    "row_key",
    "row_key_segment",
    "sealed_row_key",
    "set_decrypted",
    "table_row_key",
]
