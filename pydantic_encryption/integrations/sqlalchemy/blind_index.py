from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.engine import Dialect

from pydantic_encryption.adapters.blind_index.factory import make_blind_index, resolve_blind_index_key
from pydantic_encryption.adapters.registry import get_blind_index_backend
from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.binary import BinaryColumnType
from pydantic_encryption.normalization import (
    NormalizationFlags,
    normalize_value,
    validate_normalization_flags,
)
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class SQLAlchemyBlindIndexValue(BinaryColumnType[str | bytes]):
    """SQLAlchemy column type that stores a deterministic blind index."""

    cache_ok: bool | None = True

    def __init__(
        self,
        method: BlindIndexMethod,
        *,
        strip_whitespace: bool = False,
        strip_non_characters: bool = False,
        strip_non_digits: bool = False,
        strip_trailing_punctuation: bool = False,
        normalize_to_lowercase: bool = False,
        normalize_to_uppercase: bool = False,
    ) -> None:
        super().__init__()
        self.method = method
        self.strip_whitespace = strip_whitespace
        self.strip_non_characters = strip_non_characters
        self.strip_non_digits = strip_non_digits
        self.strip_trailing_punctuation = strip_trailing_punctuation
        self.normalize_to_lowercase = normalize_to_lowercase
        self.normalize_to_uppercase = normalize_to_uppercase

        validate_normalization_flags(self.normalization_flags)

    @property
    def normalization_flags(self) -> NormalizationFlags:
        """Return this column's normalization flags as a grouped object."""

        return NormalizationFlags(
            strip_whitespace=self.strip_whitespace,
            strip_non_characters=self.strip_non_characters,
            strip_non_digits=self.strip_non_digits,
            strip_trailing_punctuation=self.strip_trailing_punctuation,
            normalize_to_lowercase=self.normalize_to_lowercase,
            normalize_to_uppercase=self.normalize_to_uppercase,
        )

    def normalize(self, value: str | bytes) -> str | bytes:
        """Apply the configured normalization flags. Bytes values pass through unchanged."""

        if isinstance(value, bytes):
            return value

        return normalize_value(value, self.normalization_flags)

    def compute_blind_index(self, value: str | bytes) -> bytes:
        """Compute a deterministic blind index for the given value."""

        key = resolve_blind_index_key(None)
        value = self.normalize(value)
        backend = get_blind_index_backend(self.method)

        return run_async_or_sync(backend.async_compute_blind_index, backend.compute_blind_index, value, key)

    def make_blind_index_value(self, value: str | bytes, *, salt: bytes | None = None) -> BlindIndexValue:
        """Return a salted blind index using this column's own method and normalization flags."""

        return make_blind_index(
            value,
            method=self.method,
            salt=salt,
            **self.normalization_flags,
        )

    def process(self, value: str | bytes | BlindIndexValue | None) -> bytes | None:
        """Compute the blind index, passing ``None`` and pre-indexed values through."""

        if value is None:
            return None

        if isinstance(value, BlindIndexValue):
            return value

        return self.compute_blind_index(value)

    def process_bind_param(
        self, value: str | bytes | BlindIndexValue | None, dialect: Dialect
    ) -> bytes | None:
        """Compute the blind index before binding to the database."""

        return self.process(value)

    def process_result_value(self, value: bytes | None, dialect: Dialect) -> BlindIndexValue | None:
        """Return the stored blind index wrapped as a ``BlindIndexValue``."""

        if value is None:
            return None

        return BlindIndexValue(value)
