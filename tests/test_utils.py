def is_hashed(value: str) -> bool:
    """Check if a value is hashed."""

    return value.startswith("hash:")


def is_encrypted(value: str) -> bool:
    """Check if a value is encrypted."""

    return value.startswith("enc:")
