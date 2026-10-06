from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Encrypted
from pydantic_encryption.types import EncryptedValue
from tests.unit.models.utils import deferred_crypto


class TestAsyncEncryptData:
    """Test async_encrypt_data method."""

    @pytest.mark.asyncio
    async def test_async_encrypt_data(self):
        """Test that async encryption encrypts a field."""

        class _Model(BaseModel):
            secret: Annotated[str, Encrypted]

        with deferred_crypto():
            model = _Model(secret="plaintext")

        assert not isinstance(model.secret, EncryptedValue)

        await model.async_encrypt_data()
        assert isinstance(model.secret, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_encrypt_data_multiple_fields(self):
        """Test that async encryption encrypts every encrypted field."""

        class _Model(BaseModel):
            field1: Annotated[str, Encrypted]
            field2: Annotated[str, Encrypted]

        with deferred_crypto():
            model = _Model(field1="secret1", field2="secret2")

        await model.async_encrypt_data()

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)
