from abc import ABC, abstractmethod

from pydantic_encryption.types import BlindIndexValue, DecryptedValue, EncryptedValue, HashedValue


class EncryptionAdapter(ABC):
    """Abstract base class for encryption adapters."""

    @classmethod
    @abstractmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue) -> EncryptedValue:
        """Encrypt plaintext data."""

    @classmethod
    @abstractmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue) -> DecryptedValue:
        """Decrypt ciphertext data."""


class HashingAdapter(ABC):
    """Abstract base class for hashing adapters."""

    @classmethod
    @abstractmethod
    def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash the given value."""


class BlindIndexAdapter(ABC):
    """Abstract base class for blind index adapters."""

    @classmethod
    @abstractmethod
    def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic blind index for the given value."""
