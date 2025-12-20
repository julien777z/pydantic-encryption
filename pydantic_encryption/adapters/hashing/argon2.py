from typing import ClassVar

from argon2 import PasswordHasher

from pydantic_encryption.adapters.base import HashingAdapter
from pydantic_encryption.types import HashedValue


class Argon2Adapter(HashingAdapter):
    """Adapter for Argon2 hashing."""

    _hasher: ClassVar[PasswordHasher | None] = None

    @classmethod
    def _get_hasher(cls) -> PasswordHasher:
        if cls._hasher is None:
            cls._hasher = PasswordHasher()

        return cls._hasher

    @classmethod
    def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash data using Argon2.

        This function will not re-hash values that already have the 'hashed' flag set to True.
        Otherwise, it will hash the value using Argon2 and return a HashedValue.
        """

        if isinstance(value, HashedValue):
            return value

        hasher = cls._get_hasher()
        hashed_value = HashedValue(hasher.hash(value))

        return hashed_value
