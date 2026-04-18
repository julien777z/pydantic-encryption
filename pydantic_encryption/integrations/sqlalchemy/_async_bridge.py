from typing import Any, Awaitable, Callable, TypeVar

try:
    from sqlalchemy.util import await_  # type: ignore[attr-defined]  # SA 2.1+
except ImportError:
    from sqlalchemy.util import await_only as await_  # SA 2.0 fallback

from sqlalchemy.exc import MissingGreenlet

T = TypeVar("T")


def run_async_or_sync(
    async_fn: Callable[..., Awaitable[T]],
    sync_fn: Callable[..., T],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Call ``async_fn`` via SQLAlchemy's greenlet bridge; fall back to ``sync_fn``.

    Inside an ``AsyncSession`` greenlet spawn, ``await_`` suspends the calling
    frame so the event loop keeps running during slow backends (e.g. AWS KMS).
    Outside one, ``await_`` raises ``MissingGreenlet`` and we run the plain sync
    version. The awaited coroutine is always consumed or closed to avoid a
    ``RuntimeWarning: coroutine was never awaited``.
    """

    coro = async_fn(*args, **kwargs)
    try:
        return await_(coro)
    except MissingGreenlet:
        if hasattr(coro, "close"):
            coro.close()
        return sync_fn(*args, **kwargs)
