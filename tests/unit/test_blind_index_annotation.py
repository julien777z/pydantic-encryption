from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod
from pydantic_encryption.types import BlindIndexValue

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def set_blind_index_key(monkeypatch):
    """Set a test blind index secret key for all tests."""

    from pydantic_encryption import config

    monkeypatch.setattr(config.settings, "BLIND_INDEX_SECRET_KEY", "test-secret-key-for-annotation")


class TestBlindIndexAnnotationHMAC:
    """Test BlindIndex annotation with HMAC-SHA256 in Pydantic models."""

    async def test_field_is_blind_indexed(self):
        """Test that an HMAC-SHA256 BlindIndex field is hashed on async_init."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user = await UserModel.async_init(email_index="test@example.com")

        assert isinstance(user.email_index, BlindIndexValue)

    async def test_deterministic_output(self):
        """Test that equal inputs produce equal HMAC-SHA256 blind indexes."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        first = await UserModel.async_init(email_index="test@example.com")
        second = await UserModel.async_init(email_index="test@example.com")

        assert first.email_index == second.email_index

    async def test_different_inputs_different_output(self):
        """Test that different inputs produce different HMAC-SHA256 blind indexes."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        first = await UserModel.async_init(email_index="alice@example.com")
        second = await UserModel.async_init(email_index="bob@example.com")

        assert first.email_index != second.email_index

    async def test_output_is_32_bytes(self):
        """Test that the HMAC-SHA256 blind index is 32 bytes."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user = await UserModel.async_init(email_index="test@example.com")

        assert len(user.email_index) == 32


class TestBlindIndexAnnotationArgon2:
    """Test BlindIndex annotation with Argon2 in Pydantic models."""

    async def test_field_is_blind_indexed(self):
        """Test that an Argon2 BlindIndex field is hashed on async_init."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        user = await UserModel.async_init(email_index="test@example.com")

        assert isinstance(user.email_index, BlindIndexValue)
        assert len(user.email_index) == 32

    async def test_deterministic_output(self):
        """Test that equal inputs produce equal Argon2 blind indexes."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        first = await UserModel.async_init(email_index="test@example.com")
        second = await UserModel.async_init(email_index="test@example.com")

        assert first.email_index == second.email_index


class TestBlindIndexAnnotationNormalization:
    """Test BlindIndex annotation with normalization options."""

    async def test_normalize_to_lowercase(self):
        """Test that normalize_to_lowercase produces the same index regardless of case."""

        class UserModel(BaseModel):
            email_index: Annotated[
                bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True)
            ]

        first = await UserModel.async_init(email_index="Hello@Example.COM")
        second = await UserModel.async_init(email_index="hello@example.com")

        assert first.email_index == second.email_index

    async def test_strip_whitespace(self):
        """Test that strip_whitespace produces the same index regardless of whitespace."""

        class UserModel(BaseModel):
            name_index: Annotated[
                bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, strip_whitespace=True)
            ]

        first = await UserModel.async_init(name_index="  John   Doe  ")
        second = await UserModel.async_init(name_index="John Doe")

        assert first.name_index == second.name_index

    async def test_strip_non_digits(self):
        """Test that strip_non_digits produces the same index regardless of formatting."""

        class UserModel(BaseModel):
            phone_index: Annotated[
                bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, strip_non_digits=True)
            ]

        first = await UserModel.async_init(phone_index="+1 (555) 123-4567")
        second = await UserModel.async_init(phone_index="15551234567")

        assert first.phone_index == second.phone_index


class TestBlindIndexAnnotationConfig:
    """Test BlindIndex annotation configuration edge cases."""

    async def test_missing_secret_key_raises_error(self, monkeypatch):
        """Test that missing BLIND_INDEX_SECRET_KEY raises during async_init."""

        from pydantic_encryption import config

        monkeypatch.setattr(config.settings, "BLIND_INDEX_SECRET_KEY", None)

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            await UserModel.async_init(email_index="test@example.com")

    async def test_none_value_stays_none(self):
        """Test that a None-valued BlindIndex field stays None."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes | None, BlindIndex(BlindIndexMethod.HMAC_SHA256)] = None

        user = await UserModel.async_init()

        assert user.email_index is None

    @pytest.mark.asyncio(loop_scope="function")
    async def test_conflicting_strip_options_raises(self):
        """Test that contradictory strip flags are rejected at annotation definition."""

        with pytest.raises(
            ValueError, match="strip_non_characters and strip_non_digits cannot both be True"
        ):
            BlindIndex(
                BlindIndexMethod.HMAC_SHA256, strip_non_characters=True, strip_non_digits=True
            )

    @pytest.mark.asyncio(loop_scope="function")
    async def test_conflicting_case_options_raises(self):
        """Test that contradictory case flags are rejected at annotation definition."""

        with pytest.raises(
            ValueError, match="normalize_to_lowercase and normalize_to_uppercase cannot both be True"
        ):
            BlindIndex(
                BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True, normalize_to_uppercase=True
            )

    async def test_already_indexed_value_not_rehashed(self):
        """Test that passing an already-indexed BlindIndexValue into async_init leaves it unchanged."""

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        first = await UserModel.async_init(email_index="test@example.com")
        second = await UserModel.async_init(email_index=first.email_index)

        assert second.email_index == first.email_index

    async def test_different_methods_produce_different_outputs(self):
        """Test that HMAC and Argon2 blind indexes differ for the same input."""

        class UserModelHMAC(BaseModel):
            idx: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        class UserModelArgon2(BaseModel):
            idx: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        hmac_user = await UserModelHMAC.async_init(idx="test@example.com")
        argon2_user = await UserModelArgon2.async_init(idx="test@example.com")

        assert hmac_user.idx != argon2_user.idx
