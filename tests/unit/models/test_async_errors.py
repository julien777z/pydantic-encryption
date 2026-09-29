from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Encrypted
from pydantic_encryption.config import settings
from tests.unit.models.utils import deferred_crypto


class TestAsyncEncryptDataErrors:
    """Test error branches in async encrypt/decrypt methods."""

    @pytest.mark.asyncio
    async def test_async_encrypt_data_missing_method_raises(self, monkeypatch):
        """Test that async_encrypt_data raises a clear error without ENCRYPTION_METHOD."""

        class _Model(BaseModel):
            secret: Annotated[str, Encrypted]

        with deferred_crypto():
            model = _Model(secret="plaintext")

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await model.async_encrypt_data()

    @pytest.mark.asyncio
    async def test_async_decrypt_data_missing_method_raises(self, monkeypatch):
        """Test that async_decrypt_data raises a clear error without ENCRYPTION_METHOD."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="secret")
        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            await model.async_decrypt_data()

    @pytest.mark.asyncio
    async def test_async_encrypt_no_pending_fields_is_noop(self):
        """Test that async encryption of a model with no encrypted fields changes nothing."""

        class _Model(BaseModel):
            name: str

        with deferred_crypto():
            model = _Model(name="test name")

        await model.async_encrypt_data()
        assert model.name == "test name"

    @pytest.mark.asyncio
    async def test_async_decrypt_no_pending_fields_is_noop(self):
        """Test that async decryption of a model with no encrypted fields changes nothing."""

        class _Model(BaseModel):
            name: str

        with deferred_crypto():
            model = _Model(name="test name")

        result = await model.async_decrypt_data()
        assert model.name == "test name"
        assert result is model

    @pytest.mark.asyncio
    async def test_async_hash_no_pending_fields_is_noop(self):
        """Test that async hashing of a model with no hashed fields changes nothing."""

        class _Model(BaseModel):
            name: str

        with deferred_crypto():
            model = _Model(name="test name")

        await model.async_hash_data()
        assert model.name == "test name"

    @pytest.mark.asyncio
    async def test_async_blind_index_no_pending_fields_is_noop(self):
        """Test that async indexing of a model with no blind-index fields changes nothing."""

        class _Model(BaseModel):
            name: str

        with deferred_crypto():
            model = _Model(name="test name")

        await model.async_blind_index_data()
        assert model.name == "test name"
