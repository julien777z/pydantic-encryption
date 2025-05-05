try:
    from sqlalchemy.types import TypeDecorator, String
except ImportError:
    sqlalchemy_available = False
else:
    sqlalchemy_available = True

from pydantic_encryption.lib.adapters import encryption, hashing
from pydantic_encryption.annotations import EncryptionMethod
from pydantic_encryption.models.string import HashableString, EncryptableString


class SQLAlchemyEncryptedString(TypeDecorator):
    """Type adapter for SQLAlchemy to encrypt and decrypt strings using the specified encryption method."""

    impl = String
    cache_ok = True

    def __init__(
        self,
        encryption_method: EncryptionMethod,
        *args,
        **kwargs,
    ):
        if not sqlalchemy_available:
            raise ImportError(
                "SQLAlchemy is not available. Please install this package with the `sqlalchemy` extra."
            )

        if not encryption_method:
            raise ValueError("encryption_method is required")

        self.encryption_method = encryption_method

        super().__init__(*args, **kwargs)

    def _process_encrypt_value(self, value: str | bytes | None) -> str | bytes | None:
        if value is None:
            return None

        match self.encryption_method:
            case EncryptionMethod.FERNET:
                return encryption.fernet_encrypt(value)
            case EncryptionMethod.EVERVAULT:
                return encryption.evervault_encrypt(value)
            case _:
                raise ValueError(f"Unknown encryption method: {self.encryption_method}")

    def _process_decrypt_value(self, value: str | bytes | None) -> str | bytes | None:
        if value is None:
            return None

        match self.encryption_method:
            case EncryptionMethod.FERNET:
                return encryption.fernet_decrypt(value)
            case EncryptionMethod.EVERVAULT:
                return encryption.evervault_decrypt(value)
            case _:
                raise ValueError(f"Unknown encryption method: {self.encryption_method}")

    def process_bind_param(
        self, value: str | bytes | None, dialect
    ) -> str | bytes | None:
        """Encrypts a string before binding it to the database."""

        return self._process_encrypt_value(value)

    def process_literal_param(
        self, value: str | bytes | None, dialect
    ) -> str | bytes | None:
        """Encrypts a string for literal SQL expressions."""

        return self._process_encrypt_value(value)

    def process_result_value(
        self, value: str | bytes | None, dialect
    ) -> EncryptableString | None:
        """Decrypts a string after retrieving it from the database."""

        if value is None:
            return None

        decrypted_value = self._process_decrypt_value(value)

        return EncryptableString(decrypted_value, encrypted=False)

    @property
    def python_type(self):
        """Return the Python type this is bound to (str)."""
        return self.impl.python_type


class SQLAlchemyHashedString(TypeDecorator):
    """Type adapter for SQLAlchemy to hash strings using Argon2."""

    impl = String
    cache_ok = True

    def __init__(self, *args, **kwargs):
        if not sqlalchemy_available:
            raise ImportError(
                "SQLAlchemy is not available. Please install this package with the `sqlalchemy` extra."
            )

        super().__init__(*args, **kwargs)

    def process_bind_param(
        self, value: str | bytes | None, dialect
    ) -> HashableString | None:
        """Hashes a string before binding it to the database."""

        if value is None:
            return None

        return hashing.argon2_hash_data(value)

    def process_literal_param(
        self, value: str | bytes | None, dialect
    ) -> HashableString | None:
        """Hashes a string for literal SQL expressions."""

        if value is None:
            return None

        processed = hashing.argon2_hash_data(value)

        return dialect.literal_processor(self.impl)(processed)

    def process_result_value(
        self, value: str | bytes | None, dialect
    ) -> HashableString | None:
        """Returns the hash value as-is from the database, wrapped as a HashableString."""

        if value is None:
            return None

        return HashableString(value, hashed=True)

    @property
    def python_type(self):
        """Return the Python type this is bound to (str)."""
        return self.impl.python_type
