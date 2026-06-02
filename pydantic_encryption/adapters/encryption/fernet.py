from typing import ClassVar

from cryptography.fernet import Fernet

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.adapters.registry import register_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue, EncryptionMethod


class FernetAdapter(EncryptionAdapter):
    """Adapter for Fernet encryption."""

    _clients: ClassVar[dict[str, Fernet]] = {}

    @classmethod
    def _get_client(cls, key: str | None = None) -> Fernet:
        """Return a cached Fernet client for the given key (defaults to settings.ENCRYPTION_KEY)."""

        resolved = key or settings.ENCRYPTION_KEY
        if not resolved:
            raise ValueError("Fernet requires ENCRYPTION_KEY to be set.")
        if resolved not in cls._clients:
            cls._clients[resolved] = Fernet(resolved)

        return cls._clients[resolved]

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        client = cls._get_client(key)
        return EncryptedValue(client.encrypt(encode_text(plaintext)))

    @classmethod
    def decrypt(cls, ciphertext: str | bytes | EncryptedValue, *, key: str | None = None) -> str:
        client = cls._get_client(key)
        return client.decrypt(encode_text(ciphertext)).decode("utf-8")


register_encryption_backend(EncryptionMethod.FERNET, FernetAdapter)
