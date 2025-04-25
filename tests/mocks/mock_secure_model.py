from typing import Any, override
from pydantic import BaseModel as PydanticBaseModel
from pydantic_encryption.models import SecureModel


def mock_encrypt(value: str) -> str:
    """Simple mock encryption that prefixes 'enc:' to the value."""

    if isinstance(value, str) and not value.startswith("enc:"):
        return f"enc:{value}"

    return value


def mock_decrypt(value: str) -> str:
    """Simple mock decryption that removes the 'enc:' prefix."""

    if isinstance(value, str) and value.startswith("enc:"):
        return value[4:]

    return value


def mock_hash(value: str) -> str:
    """Simple mock hashing that prefixes 'hash:' to the value."""

    if isinstance(value, str) and not value.startswith("hash:"):
        return f"hash:{value}"

    return value


class MockSecureObject(SecureModel):
    """Mock implementation of SecureModel."""

    @override
    def encrypt_data(self) -> None:
        if self._disable:
            return

        if not self.pending_encryption_fields:
            return

        encrypted_data_dict = {
            field_name: mock_encrypt(value)
            for field_name, value in self.pending_encryption_fields.items()
        }

        for field_name, value in encrypted_data_dict.items():
            setattr(self, field_name, value)

    @override
    def decrypt_data(self) -> None:
        if self._disable:
            return

        if not self.pending_decryption_fields:
            return

        decrypted_data = {
            field_name: mock_decrypt(value)
            for field_name, value in self.pending_decryption_fields.items()
        }

        for field_name, value in decrypted_data.items():
            setattr(self, field_name, value)

    @override
    def hash_data(self) -> None:
        if self._disable:
            return

        if not self.pending_hash_fields:
            return

        for field_name, value in self.pending_hash_fields.items():
            hashed = mock_hash(value)

            setattr(self, field_name, hashed)


class MockBaseModel(PydanticBaseModel, MockSecureObject):
    """Mock base model."""

    _generic_type_value: Any = None

    @override
    def model_post_init(self, context: Any, /) -> None:
        if not self._disable:
            if self.pending_decryption_fields:
                self.decrypt_data()

            if self.pending_encryption_fields:
                self.encrypt_data()

            if self.pending_hash_fields:
                self.hash_data()

        super().model_post_init(context)
