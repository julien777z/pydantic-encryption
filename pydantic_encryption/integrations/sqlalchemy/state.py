from typing import Any

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm.attributes import set_committed_value

PENDING_DECRYPT_KEY = "__pydantic_encryption_pending_decrypt__"


def read_raw_cell(row: Any, column_key: str) -> Any:
    """Read a column's stored value from ORM state, bypassing attribute descriptors."""

    state = sa_inspect(row, raiseerr=False)
    if state is not None and hasattr(state, "dict"):
        return state.dict.get(column_key)
    return getattr(row, column_key, None)


def set_decrypted(row: Any, column_key: str, plaintext: Any) -> None:
    """Commit a decrypted value on a row without marking it dirty for the next flush."""

    state = sa_inspect(row, raiseerr=False)
    if state is None or not hasattr(state, "mapper"):
        setattr(row, column_key, plaintext)
        return

    set_committed_value(row, column_key, plaintext)


def row_key(mapper: Any, instance: Any) -> list[str]:
    """Return the primary key values identifying one row, one context segment each."""

    values: list[str] = []
    for column in mapper.primary_key:
        value = getattr(instance, mapper.get_property_by_column(column).key, None)
        if value is None:
            raise ValueError(
                f"Row of {mapper.class_.__name__} has no {column.key} yet, so its cells cannot bind "
                "to the row they belong to. A row-bound column needs a primary key its application "
                "assigns, or one with a client-side default; a server-generated key does not exist "
                "until after the insert it would have to be written into."
            )

        values.append(str(value))

    return values


def pending_siblings(session: Any, cls: type) -> list[Any]:
    """Return pending-decrypt instances of ``cls`` bucketed in ``session`` (empty if none)."""

    if session is None:
        return []

    bucket = getattr(session, "info", {}).get(PENDING_DECRYPT_KEY) or {}

    return list(bucket.get(cls) or [])


__all__ = ["PENDING_DECRYPT_KEY", "read_raw_cell", "row_key", "set_decrypted", "pending_siblings"]
