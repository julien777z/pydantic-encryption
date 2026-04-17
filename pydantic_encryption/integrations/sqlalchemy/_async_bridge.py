"""Bridge between SQLAlchemy's sync TypeDecorator and async adapters.

SQLAlchemy's ``AsyncSession`` runs the entire sync result-processing pipeline inside
a greenlet spawned via ``sqlalchemy.util.greenlet_spawn``. From within that spawn,
``sqlalchemy.util.await_`` yields back to the event loop while awaiting a coroutine
— the same mechanism that powers ``AsyncAttrs``. When we aren't inside a greenlet
spawn (plain sync Session), ``await_`` raises ``MissingGreenlet``.

This is a semi-private SQLAlchemy API. See discussion #10020 on the sqlalchemy repo.
"""

from typing import Any, Awaitable

try:
    from sqlalchemy.util import await_  # type: ignore[attr-defined]  # SA 2.1+
except ImportError:
    from sqlalchemy.util import await_only as await_  # SA 2.0 fallback

from sqlalchemy.exc import MissingGreenlet

_SENTINEL: Any = object()


def try_await(coro: Awaitable[Any]) -> Any:
    """Run ``coro`` inline if we're inside an AsyncSession greenlet spawn.

    Returns the awaited result, or ``_SENTINEL`` if not inside a greenlet spawn
    (caller should fall back to a sync path). The coroutine is always closed on
    the fallback path to avoid ``RuntimeWarning: coroutine was never awaited``.
    """

    try:
        return await_(coro)
    except MissingGreenlet:
        if hasattr(coro, "close"):
            coro.close()
        return _SENTINEL
