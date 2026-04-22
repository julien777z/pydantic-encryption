import asyncio
from collections.abc import Callable
from typing import Any, TypeVar

import pytest
from sqlalchemy.util import greenlet_spawn

T = TypeVar("T")


def call_in_greenlet(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a sync TypeDecorator-style call inside an SA greenlet so the async bridge works."""

    async def runner() -> T:
        return await greenlet_spawn(fn, *args, **kwargs)

    return asyncio.run(runner())


@pytest.fixture
def greenlet_runner() -> Callable[..., Any]:
    """Return a helper that runs a sync callable inside a greenlet so ``await_()`` works."""

    return call_in_greenlet
