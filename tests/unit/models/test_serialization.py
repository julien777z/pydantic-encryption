from typing import Annotated

from pydantic_encryption import BaseModel, Encrypted, Hashed


class TestModelSerialization:
    """Test model serialization with encryption."""

    def test_model_dump_contains_encrypted(self):
        """Test that model_dump carries the encrypted values."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted]

        model = _EncryptModel(secret="plaintext")
        dumped = model.model_dump()

        assert dumped["secret"] != b"plaintext"
        assert isinstance(dumped["secret"], bytes)

    def test_model_dump_contains_hashed(self):
        """Test that model_dump carries the hashed values."""

        class _HashModel(BaseModel):
            password: Annotated[str, Hashed]

        model = _HashModel(password="plaintext")
        dumped = model.model_dump()

        assert dumped["password"] != "plaintext"
        assert b"$argon2" in dumped["password"]
