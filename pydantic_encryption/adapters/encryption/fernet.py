from typing import ClassVar

from cryptography.fernet import Fernet

from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import DecryptedValue, EncryptedValue


class FernetAdapter(EncryptionAdapter):
    """Adapter for Fernet encryption."""

    _client: ClassVar[Fernet | None] = None

    @classmethod
    def _get_client(cls) -> Fernet:
        if cls._client is None:
            if not settings.ENCRYPTION_KEY:
                raise ValueError("Fernet requires ENCRYPTION_KEY to be set.")

            cls._client = Fernet(settings.ENCRYPTION_KEY)

        return cls._client

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        client = cls._get_client()
        encrypted_value = EncryptedValue(client.encrypt(plaintext))

        return encrypted_value

    @classmethod
    def decrypt(cls, ciphertext: str | bytes | EncryptedValue) -> DecryptedValue:
        if isinstance(ciphertext, DecryptedValue):
            return ciphertext

        if isinstance(ciphertext, str):
            ciphertext_bytes = ciphertext.encode("utf-8")
        else:
            ciphertext_bytes = ciphertext

        client = cls._get_client()

        decrypted_bytes = client.decrypt(ciphertext_bytes)
        decrypted_value = decrypted_bytes.decode("utf-8")

        return DecryptedValue(decrypted_value)
