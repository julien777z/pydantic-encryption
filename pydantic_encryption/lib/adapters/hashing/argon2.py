from argon2 import PasswordHasher
from pydantic_encryption.models.string import HashableString


argon2_hasher = PasswordHasher()


def argon2_hash_data(value: str | bytes | HashableString) -> HashableString:
    """Hash data using Argon2.

    This function will not re-hash values that already have the 'hashed' flag set to True
    Otherwise, it will hash the value using Argon2 and return a HashableString.
    """

    if getattr(value, "hashed", False):
        return value

    hashed_value = HashableString(argon2_hasher.hash(value))

    hashed_value.hashed = True

    return hashed_value
