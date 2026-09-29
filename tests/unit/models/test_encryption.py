from typing import Annotated

from pydantic_encryption import BaseModel, Encrypted, Hashed
from pydantic_encryption.types import EncryptedValue, HashedValue


class TestModelEncryption:
    """Test model encryption behavior."""

    def test_multiple_encrypted_fields(self):
        """Test that every encrypted field of a model is encrypted."""

        class _MultiEncrypt(BaseModel):
            field1: Annotated[str, Encrypted]
            field2: Annotated[str, Encrypted]
            field3: Annotated[str, Encrypted]

        model = _MultiEncrypt(field1="secret1", field2="secret2", field3="secret3")

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)
        assert isinstance(model.field3, EncryptedValue)

    def test_optional_encrypted_field_with_value(self):
        """Test that an optional encrypted field holding a value is encrypted."""

        class _OptionalEncrypt(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = _OptionalEncrypt(secret="my secret")

        assert isinstance(model.secret, EncryptedValue)

    def test_optional_encrypted_field_none(self):
        """Test that an optional encrypted field left None stays None."""

        class _OptionalEncrypt(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = _OptionalEncrypt()

        assert model.secret is None

    def test_optional_hashed_field_explicit_none(self):
        """Test that an optional hashed field set to None stays None."""

        class _OptionalHash(BaseModel):
            password: Annotated[str, Hashed] | None

        model = _OptionalHash(password=None)

        assert model.password is None

    def test_mixed_encrypt_and_hash(self):
        """Test that a model encrypts and hashes its fields together."""

        class _MixedModel(BaseModel):
            username: str
            email: Annotated[str, Encrypted]
            password: Annotated[str, Hashed]

        model = _MixedModel(username="test name", email="john@example.com", password="secret123")

        assert model.username == "test name"
        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    def test_model_inheritance(self):
        """Test that a subclass encrypts the fields it inherits."""

        class _BaseUser(BaseModel):
            username: str

        class _SecureUser(_BaseUser):
            password: Annotated[str, Hashed]
            secret: Annotated[str, Encrypted]

        model = _SecureUser(username="test name", password="pass123", secret="my secret")

        assert model.username == "test name"
        assert isinstance(model.password, HashedValue)
        assert isinstance(model.secret, EncryptedValue)
