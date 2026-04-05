import hashlib
import hmac

from pydantic_encryption.adapters.base import BlindIndexAdapter
from pydantic_encryption.types import BlindIndexValue


class HMACSHA256Adapter(BlindIndexAdapter):
    """Blind index adapter using HMAC-SHA256."""

    @classmethod
    def compute_blind_index(cls, value: str | bytes, key: bytes) -> BlindIndexValue:
        """Compute a deterministic HMAC-SHA256 blind index."""

        if isinstance(value, str):
            value = value.encode("utf-8")

        digest = hmac.new(key, value, hashlib.sha256).digest()

        return BlindIndexValue(digest)
