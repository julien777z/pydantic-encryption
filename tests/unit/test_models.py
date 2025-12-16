from typing import Annotated, Optional

import pytest

from pydantic_encryption import BaseModel, Decrypt, Encrypt, Hash


class TestModelEncryption:
    """Test model encryption behavior."""

    def test_multiple_encrypted_fields(self):
        """Test model with multiple encrypted fields."""

        class MultiEncrypt(BaseModel):
            field1: Annotated[bytes, Encrypt]
            field2: Annotated[bytes, Encrypt]
            field3: Annotated[bytes, Encrypt]

        model = MultiEncrypt(field1="secret1", field2="secret2", field3="secret3")

        assert getattr(model.field1, "encrypted", False)
        assert getattr(model.field2, "encrypted", False)
        assert getattr(model.field3, "encrypted", False)

    def test_optional_encrypted_field_with_value(self):
        """Test optional encrypted field with value."""

        class OptionalEncrypt(BaseModel):
            secret: Annotated[bytes, Encrypt] | None = None

        model = OptionalEncrypt(secret="my secret")

        assert getattr(model.secret, "encrypted", False)

    def test_optional_encrypted_field_none(self):
        """Test optional encrypted field with None."""

        class OptionalEncrypt(BaseModel):
            secret: Annotated[bytes, Encrypt] | None = None

        model = OptionalEncrypt()

        assert model.secret is None

    def test_mixed_encrypt_and_hash(self):
        """Test model with both encryption and hashing."""

        class MixedModel(BaseModel):
            username: str
            email: Annotated[bytes, Encrypt]
            password: Annotated[str, Hash]

        model = MixedModel(username="john", email="john@example.com", password="secret123")

        assert model.username == "john"
        assert getattr(model.email, "encrypted", False)
        assert getattr(model.password, "hashed", False)

    def test_model_inheritance(self):
        """Test encryption works with model inheritance."""

        class BaseUser(BaseModel):
            username: str

        class SecureUser(BaseUser):
            password: Annotated[str, Hash]
            secret: Annotated[bytes, Encrypt]

        model = SecureUser(username="john", password="pass123", secret="my secret")

        assert model.username == "john"
        assert getattr(model.password, "hashed", False)
        assert getattr(model.secret, "encrypted", False)

    def test_disabled_encryption_inheritance(self):
        """Test disable=True works in subclasses."""

        class DisabledModel(BaseModel, disable=True):
            secret: Annotated[bytes, Encrypt]
            password: Annotated[str, Hash]

        model = DisabledModel(secret="plaintext", password="plaintext")

        assert not getattr(model.secret, "encrypted", False)
        assert not getattr(model.password, "hashed", False)


class TestModelDecryption:
    """Test model decryption behavior."""

    def test_decrypt_field(self):
        """Test decrypting a field."""

        class EncryptModel(BaseModel):
            data: Annotated[bytes, Encrypt]

        class DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        original = "secret data"
        encrypted = EncryptModel(data=original)
        decrypted = DecryptModel(**encrypted.model_dump())

        assert decrypted.data == original

    def test_decrypt_multiple_fields(self):
        """Test decrypting multiple fields."""

        class EncryptModel(BaseModel):
            data1: Annotated[bytes, Encrypt]
            data2: Annotated[bytes, Encrypt]

        class DecryptModel(BaseModel):
            data1: Annotated[bytes, Decrypt]
            data2: Annotated[bytes, Decrypt]

        encrypted = EncryptModel(data1="secret1", data2="secret2")
        decrypted = DecryptModel(**encrypted.model_dump())

        assert decrypted.data1 == "secret1"
        assert decrypted.data2 == "secret2"


class TestModelSerialization:
    """Test model serialization with encryption."""

    def test_model_dump_contains_encrypted(self):
        """Test model_dump contains encrypted values."""

        class EncryptModel(BaseModel):
            secret: Annotated[bytes, Encrypt]

        model = EncryptModel(secret="plaintext")
        dumped = model.model_dump()

        assert dumped["secret"] != b"plaintext"
        assert isinstance(dumped["secret"], bytes)

    def test_model_dump_contains_hashed(self):
        """Test model_dump contains hashed values."""

        class HashModel(BaseModel):
            password: Annotated[str, Hash]

        model = HashModel(password="plaintext")
        dumped = model.model_dump()

        assert dumped["password"] != "plaintext"
        assert b"$argon2" in dumped["password"]


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_string_encryption(self):
        """Test encrypting empty string."""

        class Model(BaseModel):
            data: Annotated[bytes, Encrypt]

        model = Model(data="")

        assert getattr(model.data, "encrypted", False)

    def test_whitespace_string_encryption(self):
        """Test encrypting whitespace string."""

        class Model(BaseModel):
            data: Annotated[bytes, Encrypt]

        model = Model(data="   ")

        assert getattr(model.data, "encrypted", False)

    def test_unicode_encryption(self):
        """Test encrypting unicode characters."""

        class Model(BaseModel):
            data: Annotated[bytes, Encrypt]

        class DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        original = "日本語 🔐 العربية"
        encrypted = Model(data=original)
        decrypted = DecryptModel(**encrypted.model_dump())

        assert decrypted.data == original

    def test_long_string_encryption(self):
        """Test encrypting long string."""

        class Model(BaseModel):
            data: Annotated[bytes, Encrypt]

        class DecryptModel(BaseModel):
            data: Annotated[bytes, Decrypt]

        original = "x" * 10000
        encrypted = Model(data=original)
        decrypted = DecryptModel(**encrypted.model_dump())

        assert decrypted.data == original

