from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Encrypted


class TestAsyncDecryptData:
    """Test async_decrypt_data method."""

    @pytest.mark.asyncio
    async def test_async_decrypt_data(self):
        """Test that async decryption restores a field's plaintext."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="secret data")
        await model.async_decrypt_data()
        assert model.data == "secret data"

    @pytest.mark.asyncio
    async def test_async_decrypt_data_multiple(self):
        """Test that async decryption restores every encrypted field."""

        class _Model(BaseModel):
            data1: Annotated[str, Encrypted]
            data2: Annotated[str, Encrypted]

        model = _Model(data1="secret1", data2="secret2")
        await model.async_decrypt_data()

        assert model.data1 == "secret1"
        assert model.data2 == "secret2"

    @pytest.mark.asyncio
    async def test_async_decrypt_data_returns_self(self):
        """Test that async_decrypt_data returns the model for chaining."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="secret")
        result = await model.async_decrypt_data()
        assert result is model
