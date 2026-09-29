from typing import Annotated

import pytest

from pydantic_encryption import BaseModel
from pydantic_encryption.config import settings
from pydantic_encryption.types import BlindIndex, BlindIndexMethod, BlindIndexValue
from tests.unit.models.utils import deferred_crypto


class TestAsyncBlindIndexData:
    """Test async_blind_index_data method."""

    @pytest.mark.asyncio
    async def test_async_blind_index_hmac_sha256(self):
        """Test that the async phase indexes an HMAC-SHA256 field."""

        class _Model(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        with deferred_crypto():
            model = _Model(email="test@example.com")

        assert not isinstance(model.email, BlindIndexValue)

        await model.async_blind_index_data()
        assert isinstance(model.email, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_blind_index_argon2(self):
        """Test that the async phase indexes an Argon2 field."""

        class _Model(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        with deferred_crypto():
            model = _Model(email="test@example.com")

        await model.async_blind_index_data()
        assert isinstance(model.email, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_blind_index_multiple_fields(self):
        """Test that the async phase indexes every blind-index field."""

        class _Model(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]
            phone: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        with deferred_crypto():
            model = _Model(email="test@example.com", phone="1234567890")

        await model.async_blind_index_data()

        assert isinstance(model.email, BlindIndexValue)
        assert isinstance(model.phone, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_blind_index_deterministic(self):
        """Test that the async phase produces the index the sync path does."""

        class _SyncModel(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        class _AsyncModel(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        sync_model = _SyncModel(email="test@example.com")
        async_model = await _AsyncModel.async_init(email="test@example.com")

        assert sync_model.email == async_model.email

    @pytest.mark.asyncio
    async def test_async_blind_index_missing_key_raises(self, monkeypatch):
        """Test that async_blind_index_data raises a clear error without BLIND_INDEX_SECRET_KEY."""

        class _Model(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        with deferred_crypto():
            model = _Model(email="test@example.com")

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            await model.async_blind_index_data()

    @pytest.mark.asyncio
    async def test_async_blind_index_optional_none_no_key_succeeds(self, monkeypatch):
        """Test that an optional field left None needs no secret key."""

        class _Model(BaseModel):
            email: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)] | None = None

        with deferred_crypto():
            model = _Model()

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        await model.async_blind_index_data()

        assert model.email is None
