import textwrap
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Final, ParamSpec, TypeVar

import pytest
from pytest import MarkDecorator

from pydantic_encryption import BaseModel
from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.models.base import defer_crypto_to_async
from pydantic_encryption.types import EncryptedValue
from tests.cases import SEALED_CONTEXT

ModelT = TypeVar("ModelT", bound=BaseModel)
ResultT = TypeVar("ResultT")
CallP = ParamSpec("CallP")

ASYNC_PATHS: Final[MarkDecorator] = pytest.mark.parametrize(
    "asynchronous", [False, True], ids=["sync", "async"]
)

NO_SQLALCHEMY_SCRIPT: Final[str] = textwrap.dedent("""
    import sys
    from datetime import date
    from typing import Annotated


    class BlockSQLAlchemy:
        def find_module(self, name, path=None):
            return self if name == "sqlalchemy" or name.startswith("sqlalchemy.") else None

        def find_spec(self, name, path=None, target=None):
            if name == "sqlalchemy" or name.startswith("sqlalchemy."):
                raise ImportError("sqlalchemy is not installed")
            return None


    sys.meta_path.insert(0, BlockSQLAlchemy())

    from pydantic_encryption import BaseModel, Encrypted


    class Draft(BaseModel):
        dob: Annotated[date, Encrypted]


    draft = Draft(dob=date(1990, 5, 4))
    draft.decrypt_data()

    assert draft.dob == date(1990, 5, 4), draft.dob
    assert "sqlalchemy" not in sys.modules
    """)


@contextmanager
def deferred_crypto() -> Iterator[None]:
    """Hold back the sync crypto a model runs on construction for the duration of the block."""

    token = defer_crypto_to_async.set(True)
    try:
        yield
    finally:
        defer_crypto_to_async.reset(token)


async def build(model: type[ModelT], asynchronous: bool, **data: object) -> ModelT:
    """Construct a model through sync validation or ``async_init``."""

    if asynchronous:
        return await model.async_init(**data)

    return model(**data)


async def decrypt(model: ModelT, asynchronous: bool) -> ModelT:
    """Decrypt a model in place through the sync or async path, returning what that path returns."""

    if asynchronous:
        return await model.async_decrypt_data()

    return model.decrypt_data()


async def call_path(
    asynchronous: bool,
    sync_call: Callable[CallP, ResultT],
    async_call: Callable[CallP, Awaitable[ResultT]],
    /,
    *args: CallP.args,
    **kwargs: CallP.kwargs,
) -> ResultT:
    """Run an operation through its sync or async form with the same arguments."""

    if asynchronous:
        return await async_call(*args, **kwargs)

    return sync_call(*args, **kwargs)


async def seal_values(count: int, asynchronous: bool = False) -> list[EncryptedValue]:
    """Seal ``count`` distinct values one after another through the AWS adapter's sync or async path."""

    return [
        await call_path(
            asynchronous,
            AWSAdapter.encrypt,
            AWSAdapter.async_encrypt,
            f"value-{index}",
            associated_data=SEALED_CONTEXT,
        )
        for index in range(count)
    ]
