import asyncio
from typing import ClassVar

from argon2 import PasswordHasher

from pydantic_secure.adapters.base import AsyncHashingAdapter, HashingAdapter
from pydantic_secure.types import HashedValue


class Argon2Adapter(HashingAdapter, AsyncHashingAdapter):
    """Adapter for Argon2 hashing."""

    _hasher: ClassVar[PasswordHasher | None] = None

    @classmethod
    def _get_hasher(cls) -> PasswordHasher:
        if cls._hasher is None:
            cls._hasher = PasswordHasher()

        return cls._hasher

    @classmethod
    def hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        """Hash data using Argon2."""

        if isinstance(value, HashedValue):
            return value

        hasher = cls._get_hasher()
        hashed_value = HashedValue(hasher.hash(value))

        return hashed_value

    @classmethod
    async def async_hash(cls, value: str | bytes | HashedValue) -> HashedValue:
        return await asyncio.to_thread(cls.hash, value)
