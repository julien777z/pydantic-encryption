import asyncio
import hashlib
import hmac

from pydantic_encryption.adapters.base import BlindIndexAdapter
from pydantic_encryption.adapters.registry import register_blind_index_backend
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class HMACSHA256Adapter(BlindIndexAdapter):
    """Blind index adapter using HMAC-SHA256."""

    @classmethod
    def _compute_sync(cls, value: bytes, key: bytes) -> bytes:
        """Run the HMAC-SHA256 digest off the event loop."""

        return hmac.new(key, value, hashlib.sha256).digest()

    @classmethod
    async def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic HMAC-SHA256 blind index."""

        if isinstance(value, BlindIndexValue):
            return value

        if isinstance(value, str):
            value = value.encode("utf-8")

        digest = await asyncio.to_thread(cls._compute_sync, value, key)

        return BlindIndexValue(digest)


register_blind_index_backend(BlindIndexMethod.HMAC_SHA256, HMACSHA256Adapter)
