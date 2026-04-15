import asyncio
from typing import ClassVar

from cryptography.fernet import Fernet

from pydantic_secure.adapters.base import AsyncEncryptionAdapter, EncryptionAdapter
from pydantic_secure.adapters.registry import register_encryption_backend
from pydantic_secure.config import settings
from pydantic_secure.types import EncryptedValue, EncryptionMethod


class FernetAdapter(EncryptionAdapter, AsyncEncryptionAdapter):
    """Adapter for Fernet encryption."""

    _clients: ClassVar[dict[str, Fernet]] = {}

    @classmethod
    def _get_client(cls, key: str | None = None) -> Fernet:
        if key is None:
            key = settings.ENCRYPTION_KEY
        if not key:
            raise ValueError("Fernet requires ENCRYPTION_KEY to be set.")

        if key not in cls._clients:
            cls._clients[key] = Fernet(key)

        return cls._clients[key]

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        client = cls._get_client(key)
        return EncryptedValue(client.encrypt(plaintext))

    @classmethod
    def decrypt(cls, ciphertext: str | bytes | EncryptedValue, *, key: str | None = None) -> str:
        if isinstance(ciphertext, str):
            ciphertext_bytes = ciphertext.encode("utf-8")
        else:
            ciphertext_bytes = ciphertext

        client = cls._get_client(key)
        decrypted_bytes = client.decrypt(ciphertext_bytes)
        return decrypted_bytes.decode("utf-8")

    @classmethod
    async def async_encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        return await asyncio.to_thread(cls.encrypt, plaintext, key=key)

    @classmethod
    async def async_decrypt(cls, ciphertext: str | bytes | EncryptedValue, *, key: str | None = None) -> str:
        return await asyncio.to_thread(cls.decrypt, ciphertext, key=key)


register_encryption_backend(EncryptionMethod.FERNET, FernetAdapter)
