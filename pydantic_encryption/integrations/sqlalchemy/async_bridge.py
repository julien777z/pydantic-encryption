from collections.abc import Awaitable
from typing import TypeVar

try:
    from sqlalchemy.util import await_  # type: ignore[attr-defined]
except ImportError:
    from sqlalchemy.util import await_only as await_

from sqlalchemy.exc import MissingGreenlet

from pydantic_encryption.types import EncryptedValueAccessError

T = TypeVar("T")


def greenlet_await(coro: Awaitable[T], *, context: str) -> T:
    """Await a coroutine from sync code via SQLAlchemy's greenlet bridge."""

    try:
        return await_(coro)
    except MissingGreenlet:
        raise EncryptedValueAccessError(
            f"{context} requires an async-session greenlet. "
            "Use AsyncSession (or async_sessionmaker); synchronous Session is no longer supported."
        )


__all__ = ["greenlet_await"]
