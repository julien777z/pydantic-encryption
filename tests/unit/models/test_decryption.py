from typing import Annotated

from pydantic_encryption import BaseModel, Encrypted
from pydantic_encryption.types import EncryptedValue


class TestModelDecryption:
    """Test model decryption behavior using decrypt_data()."""

    def test_decrypt_data(self):
        """Test that decrypting restores a field's plaintext in place."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "secret data"
        model = _Model(data=original)

        assert isinstance(model.data, EncryptedValue)

        model.decrypt_data()

        assert model.data == original

    def test_decrypt_multiple_fields(self):
        """Test that decrypting restores every encrypted field."""

        class _Model(BaseModel):
            data1: Annotated[str, Encrypted]
            data2: Annotated[str, Encrypted]

        model = _Model(data1="secret1", data2="secret2")
        model.decrypt_data()

        assert model.data1 == "secret1"
        assert model.data2 == "secret2"

    def test_decrypt_data_returns_self(self):
        """Test that decrypt_data returns the model for chaining."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="secret")
        result = model.decrypt_data()

        assert result is model
