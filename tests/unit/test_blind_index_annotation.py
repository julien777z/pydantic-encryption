from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod
from pydantic_encryption.types import BlindIndexValue


@pytest.fixture(autouse=True)
def set_blind_index_key(monkeypatch):
    """Set a test blind index secret key for all tests."""

    from pydantic_encryption import config

    monkeypatch.setattr(config.settings, "BLIND_INDEX_SECRET_KEY", "test-secret-key-for-annotation")


class TestBlindIndexAnnotationHMAC:
    """Test BlindIndex annotation with HMAC-SHA256 in Pydantic models."""

    def test_field_is_blind_indexed(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user = UserModel(email_index="test@example.com")

        assert isinstance(user.email_index, BlindIndexValue)
        assert user.email_index.blind_indexed is True

    def test_deterministic_output(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user1 = UserModel(email_index="test@example.com")
        user2 = UserModel(email_index="test@example.com")

        assert user1.email_index == user2.email_index

    def test_different_inputs_different_output(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user1 = UserModel(email_index="alice@example.com")
        user2 = UserModel(email_index="bob@example.com")

        assert user1.email_index != user2.email_index

    def test_output_is_32_bytes(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user = UserModel(email_index="test@example.com")

        assert len(user.email_index) == 32


class TestBlindIndexAnnotationArgon2:
    """Test BlindIndex annotation with Argon2 in Pydantic models."""

    def test_field_is_blind_indexed(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        user = UserModel(email_index="test@example.com")

        assert isinstance(user.email_index, BlindIndexValue)
        assert len(user.email_index) == 32

    def test_deterministic_output(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        user1 = UserModel(email_index="test@example.com")
        user2 = UserModel(email_index="test@example.com")

        assert user1.email_index == user2.email_index


class TestBlindIndexAnnotationNormalization:
    """Test BlindIndex annotation with normalization options."""

    def test_normalize_to_lowercase(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True)]

        user1 = UserModel(email_index="Hello@Example.COM")
        user2 = UserModel(email_index="hello@example.com")

        assert user1.email_index == user2.email_index

    def test_strip_whitespace(self):
        class UserModel(BaseModel):
            name_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, strip_whitespace=True)]

        user1 = UserModel(name_index="  John   Doe  ")
        user2 = UserModel(name_index="John Doe")

        assert user1.name_index == user2.name_index

    def test_strip_non_digits(self):
        class UserModel(BaseModel):
            phone_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, strip_non_digits=True)]

        user1 = UserModel(phone_index="+1 (555) 123-4567")
        user2 = UserModel(phone_index="15551234567")

        assert user1.phone_index == user2.phone_index


class TestBlindIndexAnnotationConfig:
    """Test BlindIndex annotation configuration edge cases."""

    def test_missing_secret_key_raises_error(self, monkeypatch):
        from pydantic_encryption import config

        monkeypatch.setattr(config.settings, "BLIND_INDEX_SECRET_KEY", None)

        class UserModel(BaseModel):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            UserModel(email_index="test@example.com")

    def test_none_value_stays_none(self):
        class UserModel(BaseModel):
            email_index: Annotated[bytes | None, BlindIndex(BlindIndexMethod.HMAC_SHA256)] = None

        user = UserModel()

        assert user.email_index is None

    def test_disabled_model_skips_blind_index(self):
        class UserModel(BaseModel, disable=True):
            email_index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        user = UserModel(email_index="test@example.com")

        # Should not be blind-indexed, original value preserved (pydantic converts str to bytes)
        assert user.email_index == b"test@example.com"

    def test_conflicting_strip_options_raises(self):
        with pytest.raises(ValueError, match="strip_non_characters and strip_non_digits cannot both be True"):
            BlindIndex(BlindIndexMethod.HMAC_SHA256, strip_non_characters=True, strip_non_digits=True)

    def test_different_methods_produce_different_outputs(self):
        class UserModelHMAC(BaseModel):
            idx: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        class UserModelArgon2(BaseModel):
            idx: Annotated[bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        hmac_user = UserModelHMAC(idx="test@example.com")
        argon2_user = UserModelArgon2(idx="test@example.com")

        assert hmac_user.idx != argon2_user.idx
