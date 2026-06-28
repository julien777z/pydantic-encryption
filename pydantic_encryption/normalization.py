import re
from typing import TypedDict


class NormalizationFlags(TypedDict, total=False):
    """Grouped string-normalization flags shared across blind index helpers."""

    strip_whitespace: bool
    strip_non_characters: bool
    strip_non_digits: bool
    normalize_to_lowercase: bool
    normalize_to_uppercase: bool


def validate_normalization_flags(flags: NormalizationFlags) -> None:
    """Reject mutually exclusive normalization flag combinations."""

    if flags.get("strip_non_characters") and flags.get("strip_non_digits"):
        raise ValueError("strip_non_characters and strip_non_digits cannot both be True.")

    if flags.get("normalize_to_lowercase") and flags.get("normalize_to_uppercase"):
        raise ValueError("normalize_to_lowercase and normalize_to_uppercase cannot both be True.")


def normalize_value(value: str, flags: NormalizationFlags) -> str:
    """Apply stripping and case normalization to a string value."""

    validate_normalization_flags(flags)

    if flags.get("strip_whitespace"):
        value = re.sub(r"\s+", " ", value.strip())

    if flags.get("strip_non_characters"):
        value = re.sub(r"[^a-zA-Z]", "", value)

    if flags.get("strip_non_digits"):
        value = re.sub(r"[^0-9]", "", value)

    if flags.get("normalize_to_lowercase"):
        value = value.lower()

    if flags.get("normalize_to_uppercase"):
        value = value.upper()

    return value
