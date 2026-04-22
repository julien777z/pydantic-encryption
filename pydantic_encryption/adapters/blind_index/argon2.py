import asyncio
import hashlib

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw

from pydantic_encryption.adapters.base import BlindIndexAdapter
from pydantic_encryption.adapters.registry import register_blind_index_backend
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class Argon2BlindIndexAdapter(BlindIndexAdapter):
    """Blind index adapter using Argon2 with a deterministic salt."""

    @classmethod
    def _compute_sync(cls, value: bytes, key: bytes) -> bytes:
        """Run the Argon2 KDF off the event loop."""

        salt = hashlib.sha256(key).digest()[:16]

        return hash_secret_raw(
            secret=value,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Argon2Type.ID,
        )

    @classmethod
    async def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic Argon2 blind index."""

        if isinstance(value, BlindIndexValue):
            return value

        if isinstance(value, str):
            value = value.encode("utf-8")

        digest = await asyncio.to_thread(cls._compute_sync, value, key)

        return BlindIndexValue(digest)


register_blind_index_backend(BlindIndexMethod.ARGON2, Argon2BlindIndexAdapter)
