import bcrypt as bcrypt_provider


def bcrypt_hash_data(value: str) -> str:
    """Hash data using bcrypt."""

    salt = bcrypt_provider.gensalt()
    hashed = bcrypt_provider.hashpw(value.encode("utf-8"), salt).decode("utf-8")

    return hashed
