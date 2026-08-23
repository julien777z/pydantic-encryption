from collections.abc import Callable, Coroutine
from typing import Any, TypeVar

from sqlalchemy.exc import MissingGreenlet
from sqlalchemy.util import await_only

T = TypeVar("T")


def run_async_or_sync(
    async_fn: Callable[..., Coroutine[Any, Any, T]],
    sync_fn: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Call ``async_fn`` via SQLAlchemy's greenlet bridge; fall back to ``sync_fn`` outside one."""

    coro = async_fn(*args, **kwargs)
    try:
        return await_only(coro)
    except MissingGreenlet:
        coro.close()

        return sync_fn(*args, **kwargs)
