from abc import ABC, abstractmethod

from pydantic_secure.types import BlindIndexValue, EncryptedValue, HashedValue


class EncryptionAdapter(ABC):
    """Abstract base class for encryption adapters."""

    @classmethod
    @abstractmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        """Encrypt plaintext data."""

    @classmethod
    @abstractmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        """Decrypt ciphertext data."""


class AsyncEncryptionAdapter(ABC):
    """Abstract base class for async encryption adapters."""

    @classmethod
    @abstractmethod
    async def async_encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        """Asynchronously encrypt plaintext data."""

    @classmethod
    @abstractmethod
    async def async_decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        """Asynchronously decrypt ciphertext data."""


class HashingAdapter(ABC):
    """Abstract base class for hashing adapters."""

    @classmethod
    @abstractmethod
    def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash the given value."""


class AsyncHashingAdapter(ABC):
    """Abstract base class for async hashing adapters."""

    @classmethod
    @abstractmethod
    async def async_hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Asynchronously hash the given value."""


class BlindIndexAdapter(ABC):
    """Abstract base class for blind index adapters."""

    @classmethod
    @abstractmethod
    def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic blind index for the given value."""


class AsyncBlindIndexAdapter(ABC):
    """Abstract base class for async blind index adapters."""

    @classmethod
    @abstractmethod
    async def async_compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Asynchronously compute a deterministic blind index for the given value."""
