import asyncio
from abc import ABC, abstractmethod

from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue


class EncryptionAdapter(ABC):
    """Abstract base class for encryption adapters.

    Subclasses implement sync `encrypt` and `decrypt`. Async variants default to
    running the sync method in a thread; override them for natively-async backends.
    """

    @classmethod
    @abstractmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        """Encrypt plaintext data."""

    @classmethod
    @abstractmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        """Decrypt ciphertext data."""

    @classmethod
    async def async_encrypt(
        cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> EncryptedValue:
        return await asyncio.to_thread(cls.encrypt, plaintext, key=key)

    @classmethod
    async def async_decrypt(
        cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> str:
        return await asyncio.to_thread(cls.decrypt, ciphertext, key=key)


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
    def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic blind index for the given value."""

    @classmethod
    async def async_compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        return await asyncio.to_thread(cls.compute_blind_index, value, key)
