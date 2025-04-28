from argon2 import PasswordHasher
from pydantic_encryption.models.string import HashableString


argon2_hasher = PasswordHasher()


def argon2_hash_data(value: str | bytes | HashableString) -> HashableString:
    """Hash data using Argon2."""

    if getattr(value, "is_hashed", False):
        return value

    hashed = HashableString(argon2_hasher.hash(value))

    hashed.is_hashed = True

    return hashed
