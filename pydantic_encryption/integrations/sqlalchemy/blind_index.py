from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters.registry import get_blind_index_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.async_bridge import greenlet_await
from pydantic_encryption.normalization import normalize_value, validate_normalization_flags
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class SQLAlchemyBlindIndexValue(TypeDecorator):
    """SQLAlchemy column type that stores a deterministic blind index."""

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
    ) -> None:
        validate_normalization_flags(
            strip_non_characters=strip_non_characters,
            strip_non_digits=strip_non_digits,
            normalize_to_lowercase=normalize_to_lowercase,
            normalize_to_uppercase=normalize_to_uppercase,
        )

        super().__init__()
        self.method = method
        self.strip_whitespace = strip_whitespace
        self.strip_non_characters = strip_non_characters
        self.strip_non_digits = strip_non_digits
        self.normalize_to_lowercase = normalize_to_lowercase
        self.normalize_to_uppercase = normalize_to_uppercase

    def _key_bytes(self) -> bytes:
        if settings.BLIND_INDEX_SECRET_KEY is None:
            raise ValueError("BLIND_INDEX_SECRET_KEY must be set to use SQLAlchemyBlindIndexValue.")
        return settings.BLIND_INDEX_SECRET_KEY.encode("utf-8")

    def _normalize(self, value: str | bytes) -> str | bytes:
        """Apply the configured normalization flags. Bytes values pass through unchanged."""

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

        key = self._key_bytes()
        value = self._normalize(value)
        backend = get_blind_index_backend(self.method)

        return greenlet_await(
            backend.compute_blind_index(value, key),
            context="SQLAlchemyBlindIndexValue.compute_blind_index",
        )

    def process_bind_param(self, value: str | bytes | BlindIndexValue | None, dialect) -> bytes | None:
        """Compute the blind index before binding to the database."""

        if value is None:
            return None

        if isinstance(value, BlindIndexValue):
            return value

        return self._compute_blind_index(value)

    def process_literal_param(self, value: str | bytes | BlindIndexValue | None, dialect) -> bytes | None:
        """Compute the blind index for literal SQL expressions."""

        if value is None:
            return None

        if isinstance(value, BlindIndexValue):
            return value

        return self._compute_blind_index(value)

    def process_result_value(self, value: bytes | None, dialect) -> BlindIndexValue | None:
        """Return the stored blind index wrapped as a ``BlindIndexValue``."""

        if value is None:
            return None

        return BlindIndexValue(value)

    @property
    def python_type(self):
        """Return the Python type this column is bound to."""

        return self.impl.python_type
