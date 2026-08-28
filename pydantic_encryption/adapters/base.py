import asyncio
from abc import ABC, abstractmethod

from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue


def encode_text(value: str | bytes) -> bytes:
    """Return UTF-8 bytes for a ``str``, or the bytes unchanged."""

    return value.encode("utf-8") if isinstance(value, str) else value


def fold_salt(message: bytes, salt: bytes | None) -> bytes:
    """Prepend a length-tagged salt so the salt/message join stays unambiguous across salt lengths."""

    if salt is None:
        return message

    return len(salt).to_bytes(4, "big") + salt + message


class EncryptionAdapter(ABC):
    """Abstract base class for encryption adapters.

    ``associated_data`` binds a ciphertext to the context it belongs to -- a column, a row, a
    tenant -- and is required, so no caller can leave a value interchangeable with every other by
    omission. It is authenticated but never stored, so decrypt must be given the same bytes
    encrypt was; a ciphertext moved to another context fails to open rather than decrypting into
    it. A backend whose primitive cannot authenticate associated data binds the context some other
    way -- never by accepting the argument and ignoring it.
    """

    @classmethod
    @abstractmethod
    def encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        """Encrypt plaintext data, binding it to associated data when given."""

    @classmethod
    @abstractmethod
    def decrypt(
        cls,
        ciphertext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> str:
        """Decrypt ciphertext data, requiring the associated data it was bound to."""

    @classmethod
    async def async_encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        return await asyncio.to_thread(cls.encrypt, plaintext, key=key, associated_data=associated_data)

    @classmethod
    async def async_decrypt(
        cls,
        ciphertext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> str:
        return await asyncio.to_thread(cls.decrypt, ciphertext, key=key, associated_data=associated_data)


class HashingAdapter(ABC):
    """Abstract base class for hashing adapters."""

    @classmethod
    @abstractmethod
    def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash the given value."""

    @classmethod
    async def async_hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        return await asyncio.to_thread(cls.hash, value)


class BlindIndexAdapter(ABC):
    """Abstract base class for blind index adapters."""

    @classmethod
    @abstractmethod
    def compute_blind_index(
        cls, value: str | bytes, key: bytes, *, salt: bytes | None = None
    ) -> BlindIndexValue:
        """Compute a deterministic blind index for the given value, optionally salted."""

    @classmethod
    async def async_compute_blind_index(
        cls, value: str | bytes, key: bytes, *, salt: bytes | None = None
    ) -> BlindIndexValue:
        return await asyncio.to_thread(cls.compute_blind_index, value, key, salt=salt)
