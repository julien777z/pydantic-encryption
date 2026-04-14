import asyncio
import hashlib
import hmac

from pydantic_encryption.adapters.base import AsyncBlindIndexAdapter, BlindIndexAdapter
from pydantic_encryption.types import BlindIndexValue


class HMACSHA256Adapter(BlindIndexAdapter, AsyncBlindIndexAdapter):
    """Blind index adapter using HMAC-SHA256."""

    @classmethod
    def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic HMAC-SHA256 blind index."""

        if isinstance(value, BlindIndexValue):
            return value

        if isinstance(value, str):
            value = value.encode("utf-8")

        digest = hmac.new(key, value, hashlib.sha256).digest()

        return BlindIndexValue(digest)

    @classmethod
    async def async_compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        return await asyncio.to_thread(cls.compute_blind_index, value, key)
