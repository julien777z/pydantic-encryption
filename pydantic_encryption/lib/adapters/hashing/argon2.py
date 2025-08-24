from argon2 import PasswordHasher
from pydantic_encryption.models.encryptable import HashedValue


argon2_hasher = PasswordHasher()


def argon2_hash_data(value: str | bytes | HashedValue) -> HashedValue:
    """Hash data using Argon2.

    This function will not re-hash values that already have the 'hashed' flag set to True
    Otherwise, it will hash the value using Argon2 and return a HashableString.
    """

    if isinstance(value, HashedValue):
        return value

    hashed_value = HashedValue(argon2_hasher.hash(value))

    return hashed_value
