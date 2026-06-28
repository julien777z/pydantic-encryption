import hashlib
import hmac

from pydantic_encryption.adapters.base import BlindIndexAdapter, encode_text
from pydantic_encryption.adapters.registry import register_blind_index_backend
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class HMACSHA256Adapter(BlindIndexAdapter):
    """Blind index adapter using HMAC-SHA256."""

    @classmethod
    def compute_blind_index(
        cls, value: str | bytes, key: bytes, *, salt: bytes | None = None
    ) -> BlindIndexValue:
        """Compute a deterministic HMAC-SHA256 blind index, optionally salted."""

        if isinstance(value, BlindIndexValue):
            return value

        message = encode_text(value)

        if salt is not None:
            message = salt + message

        digest = hmac.new(key, message, hashlib.sha256).digest()

        return BlindIndexValue(digest)


register_blind_index_backend(BlindIndexMethod.HMAC_SHA256, HMACSHA256Adapter)
