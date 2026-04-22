import asyncio
from typing import ClassVar

from argon2 import PasswordHasher

from pydantic_encryption.adapters.base import HashingAdapter
from pydantic_encryption.types import HashedValue


class Argon2Adapter(HashingAdapter):
    """Adapter for Argon2 hashing."""

    _hasher: ClassVar[PasswordHasher | None] = None

    @classmethod
    def _get_hasher(cls) -> PasswordHasher:
        """Return a cached PasswordHasher instance."""

        if cls._hasher is None:
            cls._hasher = PasswordHasher()

        return cls._hasher

    @classmethod
    async def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash data using Argon2."""

        if isinstance(value, HashedValue):
            return value

        hasher = cls._get_hasher()
        hashed = await asyncio.to_thread(hasher.hash, value)

        return HashedValue(hashed)
