from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Hashed
from pydantic_encryption.types import HashedValue
from tests.unit.models.utils import deferred_crypto


class TestAsyncHashData:
    """Test async_hash_data method."""

    @pytest.mark.asyncio
    async def test_async_hash_data(self):
        """Test that async hashing hashes a field."""

        class _Model(BaseModel):
            password: Annotated[str, Hashed]

        with deferred_crypto():
            model = _Model(password="secret123")

        assert not isinstance(model.password, HashedValue)

        await model.async_hash_data()
        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_hash_data_multiple_fields(self):
        """Test that async hashing hashes every hashed field."""

        class _Model(BaseModel):
            password1: Annotated[str, Hashed]
            password2: Annotated[str, Hashed]

        with deferred_crypto():
            model = _Model(password1="secret1", password2="secret2")

        await model.async_hash_data()

        assert isinstance(model.password1, HashedValue)
        assert isinstance(model.password2, HashedValue)
