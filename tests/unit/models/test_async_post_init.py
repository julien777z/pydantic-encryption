from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Encrypted, Hashed
from pydantic_encryption.types import EncryptedValue, HashedValue
from tests.unit.models.utils import deferred_crypto


class TestAsyncPostInit:
    """Test async_post_init method."""

    @pytest.mark.asyncio
    async def test_async_post_init_encrypt_and_hash(self):
        """Test that async_post_init encrypts and hashes the model's fields."""

        class _Model(BaseModel):
            email: Annotated[str, Encrypted]
            password: Annotated[str, Hashed]

        with deferred_crypto():
            model = _Model(email="user@example.com", password="secret123")

        assert not isinstance(model.email, EncryptedValue)
        assert not isinstance(model.password, HashedValue)

        await model.async_post_init()

        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_post_init_then_decrypt(self):
        """Test that fields async_post_init encrypts decrypt with async_decrypt_data."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        with deferred_crypto():
            model = _Model(data="secret")

        await model.async_post_init()
        assert isinstance(model.data, EncryptedValue)

        await model.async_decrypt_data()
        assert model.data == "secret"
