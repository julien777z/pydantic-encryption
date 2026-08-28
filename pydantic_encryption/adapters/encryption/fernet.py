import base64
from typing import ClassVar

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.adapters.registry import register_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue, EncryptionMethod

FERNET_KEY_LENGTH: int = 32


def derive_context_key(root_key: str, associated_data: bytes) -> bytes:
    """Derive the Fernet key one context is sealed under, from the configured root key."""

    derived = HKDF(
        algorithm=SHA256(),
        length=FERNET_KEY_LENGTH,
        salt=None,
        info=associated_data,
    ).derive(root_key.encode("utf-8"))

    return base64.urlsafe_b64encode(derived)


class FernetAdapter(EncryptionAdapter):
    """Adapter for Fernet encryption.

    A Fernet token has no field that authenticates associated data, so the context is bound by key
    separation instead: every context gets its own key derived from the configured root key, and a
    ciphertext carried into another context fails its authentication check there.
    """

    _clients: ClassVar[dict[tuple[str, bytes], Fernet]] = {}

    @classmethod
    def get_client(cls, key: str | None, associated_data: bytes) -> Fernet:
        """Return the cached Fernet client for one context under the given root key."""

        resolved = key or settings.ENCRYPTION_KEY
        if not resolved:
            raise ValueError("Fernet requires ENCRYPTION_KEY to be set.")

        cache_key = (resolved, associated_data)
        if cache_key not in cls._clients:
            cls._clients[cache_key] = Fernet(derive_context_key(resolved, associated_data))

        return cls._clients[cache_key]

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        client = cls.get_client(key, associated_data)

        return EncryptedValue(client.encrypt(encode_text(plaintext)))

    @classmethod
    def decrypt(
        cls,
        ciphertext: str | bytes | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> str:
        client = cls.get_client(key, associated_data)

        return client.decrypt(encode_text(ciphertext)).decode("utf-8")


register_encryption_backend(EncryptionMethod.FERNET, FernetAdapter)
