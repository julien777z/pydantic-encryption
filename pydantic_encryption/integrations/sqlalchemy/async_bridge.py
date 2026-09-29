from collections.abc import Callable, Coroutine
from typing import Never, ParamSpec, TypeVar

from sqlalchemy.exc import MissingGreenlet
from sqlalchemy.util import await_only

P = ParamSpec("P")
T = TypeVar("T")


def run_async_or_sync(
    async_fn: Callable[P, Coroutine[object, Never, T]],
    sync_fn: Callable[P, T],
    *args: P.args,
    **kwargs: P.kwargs,
) -> T:
    """Call ``async_fn`` via SQLAlchemy's greenlet bridge; fall back to ``sync_fn`` outside one."""

    coro = async_fn(*args, **kwargs)
    try:
        return await_only(coro)
    except MissingGreenlet:
        coro.close()

        return sync_fn(*args, **kwargs)
