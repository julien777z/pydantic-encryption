import asyncio
from typing import ClassVar

from cryptography.fernet import Fernet

from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.adapters.registry import register_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue, EncryptionMethod


class FernetAdapter(EncryptionAdapter):
    """Adapter for Fernet encryption."""

    _clients: ClassVar[dict[str, Fernet]] = {}

    @classmethod
    def _get_client(cls, key: str | None = None) -> Fernet:
        """Return a cached Fernet client for the given key."""

        if key is None:
            key = settings.ENCRYPTION_KEY
        if not key:
            raise ValueError("Fernet requires ENCRYPTION_KEY to be set.")

        if key not in cls._clients:
            cls._clients[key] = Fernet(key)

        return cls._clients[key]

    @classmethod
    async def encrypt(
        cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        client = cls._get_client(key)
        ciphertext = await asyncio.to_thread(client.encrypt, plaintext)

        return EncryptedValue(ciphertext)

    @classmethod
    async def decrypt(
        cls, ciphertext: str | bytes | EncryptedValue, *, key: str | None = None
    ) -> str:
        if isinstance(ciphertext, str):
            ciphertext_bytes = ciphertext.encode("utf-8")
        else:
            ciphertext_bytes = ciphertext

        client = cls._get_client(key)
        plaintext_bytes = await asyncio.to_thread(client.decrypt, ciphertext_bytes)

        return plaintext_bytes.decode("utf-8")


register_encryption_backend(EncryptionMethod.FERNET, FernetAdapter)
