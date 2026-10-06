from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, Encrypted, Hashed
from pydantic_encryption.types import EncryptedValue, HashedValue


class TestAsyncInit:
    """Test BaseModel.async_init produces same results as sync construction."""

    @pytest.mark.asyncio
    async def test_async_init_encrypts_fields(self):
        """Test that async_init encrypts an encrypted field."""

        class _Model(BaseModel):
            secret: Annotated[str, Encrypted]

        model = await _Model.async_init(secret="plaintext")

        assert isinstance(model.secret, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_hashes_fields(self):
        """Test that async_init hashes a hashed field."""

        class _Model(BaseModel):
            password: Annotated[str, Hashed]

        model = await _Model.async_init(password="secret123")

        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_init_mixed_encrypt_and_hash(self):
        """Test that async_init encrypts and hashes while leaving plain fields alone."""

        class _Model(BaseModel):
            username: str
            email: Annotated[str, Encrypted]
            password: Annotated[str, Hashed]

        model = await _Model.async_init(username="test name", email="test@example.com", password="secret123")

        assert model.username == "test name"
        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    @pytest.mark.asyncio
    async def test_async_init_multiple_encrypted_fields(self):
        """Test that async_init encrypts every encrypted field."""

        class _Model(BaseModel):
            field1: Annotated[str, Encrypted]
            field2: Annotated[str, Encrypted]
            field3: Annotated[str, Encrypted]

        model = await _Model.async_init(field1="secret1", field2="secret2", field3="secret3")

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)
        assert isinstance(model.field3, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_optional_encrypted_field_with_value(self):
        """Test that async_init encrypts an optional field holding a value."""

        class _Model(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = await _Model.async_init(secret="my secret")

        assert isinstance(model.secret, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_init_optional_encrypted_field_none(self):
        """Test that async_init leaves an optional field set to None as None."""

        class _Model(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = await _Model.async_init()

        assert model.secret is None

    @pytest.mark.asyncio
    async def test_async_init_decryptable(self):
        """Test that values async_init encrypts decrypt with async_decrypt_data."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "secret data"
        model = await _Model.async_init(data=original)

        assert isinstance(model.data, EncryptedValue)

        await model.async_decrypt_data()
        assert model.data == original

    @pytest.mark.asyncio
    async def test_async_init_pydantic_validation_still_runs(self):
        """Test that async_init still runs pydantic validation."""

        class _Model(BaseModel):
            age: int
            secret: Annotated[str, Encrypted]

        with pytest.raises(Exception):
            await _Model.async_init(age="not_a_number", secret="test")

    @pytest.mark.asyncio
    async def test_async_init_sync_still_works_after(self):
        """Test that sync construction still encrypts after async_init has run."""

        class _Model(BaseModel):
            secret: Annotated[str, Encrypted]

        async_model = await _Model.async_init(secret="async_secret")
        sync_model = _Model(secret="sync_secret")

        assert isinstance(async_model.secret, EncryptedValue)
        assert isinstance(sync_model.secret, EncryptedValue)
