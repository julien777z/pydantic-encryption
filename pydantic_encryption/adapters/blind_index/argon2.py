import hashlib

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw

from pydantic_encryption.adapters.base import BlindIndexAdapter, encode_text
from pydantic_encryption.adapters.registry import register_blind_index_backend
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class Argon2BlindIndexAdapter(BlindIndexAdapter):
    """Blind index adapter using Argon2 with a deterministic salt."""

    @classmethod
    def compute_blind_index(
        cls, value: str | bytes, key: bytes, *, salt: bytes | None = None
    ) -> BlindIndexValue:
        """Compute a deterministic Argon2 blind index, optionally salted."""

        if isinstance(value, BlindIndexValue):
            return value

        secret = encode_text(value)

        if salt is not None:
            secret = salt + secret

        argon2_salt = hashlib.sha256(key).digest()[:16]
        digest = hash_secret_raw(
            secret=secret,
            salt=argon2_salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Argon2Type.ID,
        )

        return BlindIndexValue(digest)


register_blind_index_backend(BlindIndexMethod.ARGON2, Argon2BlindIndexAdapter)
