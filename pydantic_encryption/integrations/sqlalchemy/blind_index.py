from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.config import settings
from pydantic_encryption.normalization import normalize_value
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class SQLAlchemyBlindIndexValue(TypeDecorator):
    """Type adapter for SQLAlchemy to create deterministic blind indexes."""

    impl = LargeBinary
    cache_ok = True

    def __init__(
        self,
        method: BlindIndexMethod,
        *,
        strip_whitespace: bool = False,
        strip_non_characters: bool = False,
        strip_non_digits: bool = False,
        normalize_to_lowercase: bool = False,
        normalize_to_uppercase: bool = False,
    ):
        if strip_non_characters and strip_non_digits:
            raise ValueError("strip_non_characters and strip_non_digits cannot both be True.")

        if normalize_to_lowercase and normalize_to_uppercase:
            raise ValueError("normalize_to_lowercase and normalize_to_uppercase cannot both be True.")

        super().__init__()
        self.method = method
        self.strip_whitespace = strip_whitespace
        self.strip_non_characters = strip_non_characters
        self.strip_non_digits = strip_non_digits
        self.normalize_to_lowercase = normalize_to_lowercase
        self.normalize_to_uppercase = normalize_to_uppercase

    def _get_key_bytes(self) -> bytes:
        if settings.BLIND_INDEX_SECRET_KEY is None:
            raise ValueError("BLIND_INDEX_SECRET_KEY must be set to use SQLAlchemyBlindIndexValue.")
        return settings.BLIND_INDEX_SECRET_KEY.encode("utf-8")

    def _normalize_value(self, value: str | bytes) -> str | bytes:
        """Apply normalization to the value before hashing."""

        if isinstance(value, bytes):
            return value

        return normalize_value(
            value,
            strip_whitespace=self.strip_whitespace,
            strip_non_characters=self.strip_non_characters,
            strip_non_digits=self.strip_non_digits,
            normalize_to_lowercase=self.normalize_to_lowercase,
            normalize_to_uppercase=self.normalize_to_uppercase,
        )

    def _compute_blind_index(self, value: str | bytes) -> bytes:
        """Compute a deterministic blind index for the given value."""

        key = self._get_key_bytes()
        value = self._normalize_value(value)

        match self.method:
            case BlindIndexMethod.HMAC_SHA256:
                return HMACSHA256Adapter.compute_blind_index(value, key)
            case BlindIndexMethod.ARGON2:
                from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter

                return Argon2BlindIndexAdapter.compute_blind_index(value, key)
            case _:
                raise ValueError(f"Unknown blind index method: {self.method}")

    def process_bind_param(self, value: str | bytes | BlindIndexValue | None, dialect) -> bytes | None:
        """Computes the blind index before binding to the database."""

        if value is None:
            return None

        if isinstance(value, BlindIndexValue):
            return value

        return self._compute_blind_index(value)

    def process_literal_param(self, value: str | bytes | BlindIndexValue | None, dialect) -> bytes | None:
        """Computes the blind index for literal SQL expressions."""

        if value is None:
            return None

        if isinstance(value, BlindIndexValue):
            return value

        return self._compute_blind_index(value)

    def process_result_value(self, value: bytes | None, dialect) -> BlindIndexValue | None:
        """Returns the blind index value as-is from the database."""

        if value is None:
            return None

        return BlindIndexValue(value)

    @property
    def python_type(self):
        """Return the Python type this is bound to."""

        return self.impl.python_type
