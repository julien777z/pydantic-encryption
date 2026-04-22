from typing import Any

from pydantic_encryption._lazy import require_optional_dependency

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


def pending_siblings(session: Any, cls: type) -> list[Any]:
    """Return pending-decrypt instances of ``cls`` bucketed in ``session`` (empty if none)."""

    if session is None:
        return []
    info = getattr(session, "info", None)
    if not info:
        return []
    bucket = info.get(PENDING_DECRYPT_KEY)
    if not bucket:
        return []
    siblings = bucket.get(cls)
    if siblings is None:
        return []
    return list(siblings)


__all__ = ["PENDING_DECRYPT_KEY", "read_raw_cell", "set_decrypted", "pending_siblings"]
