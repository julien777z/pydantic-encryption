from typing import Annotated

import pytest

from pydantic_encryption import BaseModel
from pydantic_encryption.types import BlindIndex, BlindIndexMethod, BlindIndexValue


class TestAsyncApplyGuards:
    """Test what the async phases do when a model gives them nothing to do."""

    @pytest.mark.asyncio
    async def test_applying_no_items_touches_nothing(self):
        """Test that a phase with nothing to await returns without opening a task group."""

        class NoFieldsUser(BaseModel):
            name: str

        user = NoFieldsUser(name="plain")

        await user.async_apply([])

        assert user.name == "plain"

    @pytest.mark.asyncio
    async def test_str_field_indexed_as_it_stands(self):
        """Test that a value already held as a str is indexed without being decoded first."""

        class StringIndexUser(BaseModel):
            index: Annotated[str, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user = await StringIndexUser.async_init(index="john@example.com")

        assert isinstance(user.index, BlindIndexValue)
