try:
    from sqlalchemy.types import TypeDecorator, String
except ImportError:
    sqlalchemy_available = False
else:
    sqlalchemy_available = True

from pydantic_encryption.lib.adapters.encryption.fernet import (
    fernet_encrypt,
    fernet_decrypt,
)
from pydantic_encryption.lib.adapters.encryption.evervault import (
    evervault_encrypt,
    evervault_decrypt,
)
from pydantic_encryption.lib.adapters.hashing.argon2 import argon2_hash_data
from pydantic_encryption.annotations import EncryptionMethod


class SQLAlchemyEncryptedString(TypeDecorator):
    """Encrypts and decrypts strings using Fernet."""

    impl = String
    cache_ok = True

    def __init__(
        self,
        *args,
        **kwargs,
    ):
        if not sqlalchemy_available:
            raise ImportError(
                "SQLAlchemy is not available. Please install this package with the `sqlalchemy` extra."
            )

        self.encryption_method = kwargs.pop("encryption_method")

        if not self.encryption_method:
            raise ValueError("encryption_method is required")

        super().__init__(*args, **kwargs)

    def process_bind_param(self, value: str | bytes | None, dialect):
        """Encrypts a string before binding it to the database."""

        if value is None:
            return None

        match self.encryption_method:
            case EncryptionMethod.FERNET:
                return fernet_encrypt(value)
            case EncryptionMethod.EVERVAULT:
                return evervault_encrypt(value)
            case _:
                raise ValueError(f"Unknown encryption method: {self.encryption_method}")

    def process_result_value(self, value: str | bytes | None, dialect):
        """Decrypts a string after retrieving it from the database."""

        if value is None:
            return None

        match self.encryption_method:
            case EncryptionMethod.FERNET:
                return fernet_decrypt(value)
            case EncryptionMethod.EVERVAULT:
                return evervault_decrypt(value)
            case _:
                raise ValueError(f"Unknown encryption method: {self.encryption_method}")


class SQLAlchemyHashedString(TypeDecorator):
    """Encrypts and decrypts strings using Argon2."""

    impl = String
    cache_ok = True

    def __init__(self, *args, **kwargs):
        if not sqlalchemy_available:
            raise ImportError(
                "SQLAlchemy is not available. Please install this package with the `sqlalchemy` extra."
            )

        super().__init__(*args, **kwargs)

    def process_bind_param(self, value: str | bytes | None, dialect):
        """Encrypts a string before binding it to the database."""

        if value is None:
            return None

        return argon2_hash_data(value)

    def process_result_value(self, value: str | bytes | None, dialect):
        """Decrypts a string after retrieving it from the database."""

        if value is None:
            return None

        return argon2_hash_data(value)
