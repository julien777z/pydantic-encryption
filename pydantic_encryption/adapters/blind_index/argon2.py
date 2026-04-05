import hashlib

from pydantic_encryption.adapters.base import BlindIndexAdapter
from pydantic_encryption.types import BlindIndexValue


class Argon2BlindIndexAdapter(BlindIndexAdapter):
    """Blind index adapter using Argon2 with a deterministic salt."""

    @classmethod
    def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic Argon2 blind index.

        Uses a fixed salt derived from SHA-256 of the key to ensure
        deterministic output while preserving Argon2's computational hardness.
        """

        from argon2.low_level import Type as Argon2Type
        from argon2.low_level import hash_secret_raw

        if isinstance(value, str):
            value = value.encode("utf-8")

        salt = hashlib.sha256(key).digest()[:16]
        digest = hash_secret_raw(
            secret=value,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Argon2Type.ID,
        )

        return BlindIndexValue(digest)
