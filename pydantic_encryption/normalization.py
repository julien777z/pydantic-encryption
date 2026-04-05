import re


def normalize_value(
    value: str,
    *,
    strip_whitespace: bool = False,
    strip_non_characters: bool = False,
    strip_non_digits: bool = False,
    normalize_to_lowercase: bool = False,
    normalize_to_uppercase: bool = False,
) -> str:
    """Apply stripping and normalization transformations to a value.

    Stripping options remove characters, normalization options transform case.
    Applied in order: whitespace → characters → digits → lowercase → uppercase.
    """

    if strip_whitespace:
        value = re.sub(r"\s+", " ", value.strip())

    if strip_non_characters:
        value = re.sub(r"[^a-zA-Z]", "", value)

    if strip_non_digits:
        value = re.sub(r"[^0-9]", "", value)

    if normalize_to_lowercase:
        value = value.lower()

    if normalize_to_uppercase:
        value = value.upper()

    return value
