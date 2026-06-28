from pydantic_encryption.adapters.registry import get_blind_index_backend
from pydantic_encryption.config import settings
from pydantic_encryption.normalization import normalize_value, validate_normalization_flags
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


def make_blind_index(
    value: str | bytes,
    *,
    method: BlindIndexMethod,
    salt: bytes | None = None,
    strip_whitespace: bool = False,
    strip_non_characters: bool = False,
    strip_non_digits: bool = False,
    normalize_to_lowercase: bool = False,
    normalize_to_uppercase: bool = False,
    key: str | bytes | None = None,
) -> BlindIndexValue:
    """Compute a deterministic, optionally per-row-salted blind index for a value."""

    if isinstance(value, BlindIndexValue):
        return value

    validate_normalization_flags(
        strip_non_characters=strip_non_characters,
        strip_non_digits=strip_non_digits,
        normalize_to_lowercase=normalize_to_lowercase,
        normalize_to_uppercase=normalize_to_uppercase,
    )

    resolved_key = key if key is not None else settings.BLIND_INDEX_SECRET_KEY

    if resolved_key is None:
        raise ValueError("BLIND_INDEX_SECRET_KEY must be set to compute a blind index.")

    key_bytes = resolved_key.encode("utf-8") if isinstance(resolved_key, str) else resolved_key

    normalized = (
        value
        if isinstance(value, bytes)
        else normalize_value(
            value,
            strip_whitespace=strip_whitespace,
            strip_non_characters=strip_non_characters,
            strip_non_digits=strip_non_digits,
            normalize_to_lowercase=normalize_to_lowercase,
            normalize_to_uppercase=normalize_to_uppercase,
        )
    )

    backend = get_blind_index_backend(method)

    return backend.compute_blind_index(normalized, key_bytes, salt=salt)
