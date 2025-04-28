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


class SQLAlchemyEncryptedString(TypeDecorator):
    """Encrypts and decrypts strings using Fernet."""

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

        return fernet_encrypt(value)

    def process_result_value(self, value: str | bytes | None, dialect):
        """Decrypts a string after retrieving it from the database."""

        if value is None:
            return None

        return fernet_decrypt(value)
