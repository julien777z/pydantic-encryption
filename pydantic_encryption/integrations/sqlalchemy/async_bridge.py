from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

try:
    from sqlalchemy.util import await_  # type: ignore[attr-defined]
except ImportError:
    from sqlalchemy.util import await_only as await_

from sqlalchemy.exc import MissingGreenlet

T = TypeVar("T")


def run_async_or_sync(
    async_fn: Callable[..., Awaitable[T]],
    sync_fn: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Call ``async_fn`` via SQLAlchemy's greenlet bridge; fall back to ``sync_fn`` outside one."""

    coro = async_fn(*args, **kwargs)
    try:
        return await_(coro)
    except MissingGreenlet:
        coro.close()

        return sync_fn(*args, **kwargs)
