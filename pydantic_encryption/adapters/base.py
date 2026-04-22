from abc import ABC, abstractmethod

from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue


class EncryptionAdapter(ABC):
    """Abstract base class for async encryption adapters."""

    @classmethod
    @abstractmethod
    async def encrypt(
        cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> EncryptedValue:
        """Encrypt plaintext data."""

    @classmethod
    @abstractmethod
    async def decrypt(
        cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> str:
        """Decrypt ciphertext data."""


class HashingAdapter(ABC):
    """Abstract base class for async hashing adapters."""

    @classmethod
    @abstractmethod
    async def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash the given value."""


class BlindIndexAdapter(ABC):
    """Abstract base class for async blind index adapters."""

    @classmethod
    @abstractmethod
    async def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic blind index for the given value."""
