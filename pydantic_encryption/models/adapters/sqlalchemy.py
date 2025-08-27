try:
    from sqlalchemy.types import LargeBinary, TypeDecorator

    _SQLALCHEMY_AVAILABLE = True
except ImportError:
    _SQLALCHEMY_AVAILABLE = False

from pydantic_encryption.annotations import EncryptionMethod
from pydantic_encryption.config import settings
from pydantic_encryption.lib.adapters import encryption, hashing
from pydantic_encryption.models.encryptable import DecryptedValue, EncryptedValue, HashedValue

if not _SQLALCHEMY_AVAILABLE:

    class _MissingSQLAlchemy:
        """Placeholder that raises an ImportError when instantiated."""

        def __init__(self, *args, **kwargs):
            raise ImportError(
                "SQLAlchemy is not available. Please install this package with the `sqlalchemy` extra."
            )

    class SQLAlchemyEncrypted(_MissingSQLAlchemy):
        pass

    class SQLAlchemyHashed(_MissingSQLAlchemy):
        pass

else:

    class SQLAlchemyEncrypted(TypeDecorator):
        """Type adapter for SQLAlchemy to encrypt and decrypt strings using the specified encryption method."""

        impl = LargeBinary
        cache_ok = True

        def __init__(
            self,
            *args,
            **kwargs,
        ):
            super().__init__(*args, **kwargs)

        def _process_encrypt_value(self, value: str | bytes | None) -> EncryptedValue | None:
            if value is None:
                return None

            match settings.ENCRYPTION_METHOD:
                case EncryptionMethod.FERNET:
                    # optional_import returns a sentinel that raises on use; no inline checks needed
                    return encryption.fernet.fernet_encrypt(value)
                case EncryptionMethod.EVERVAULT:
                    # raises with clear message if missing
                    return encryption.evervault.evervault_encrypt(value)
                case EncryptionMethod.AWS:
                    # raises with clear message if missing
                    return encryption.aws.aws_encrypt(value)

        def _process_decrypt_value(self, value: str | bytes | None) -> str | bytes | None:
            if value is None:
                return None

            match settings.ENCRYPTION_METHOD:
                case EncryptionMethod.FERNET:
                    # raises if missing
                    return encryption.fernet.fernet_decrypt(value)
                case EncryptionMethod.EVERVAULT:
                    # raises if missing
                    return encryption.evervault.evervault_decrypt(value)
                case EncryptionMethod.AWS:
                    # raises if missing
                    value = encryption.aws.aws_decrypt(value)
                    return value

        def process_bind_param(self, value: str | bytes | None, dialect) -> str | bytes | None:
            """Encrypts a string before binding it to the database."""

            return self._process_encrypt_value(value)

        def process_literal_param(self, value: str | bytes | None, dialect) -> str | bytes | None:
            """Encrypts a string for literal SQL expressions."""

            return self._process_encrypt_value(value)

        def process_result_value(self, value: str | bytes | None, dialect) -> DecryptedValue | None:
            """Decrypts a string after retrieving it from the database."""

            if value is None:
                return None

            decrypted_value = self._process_decrypt_value(value)

            return DecryptedValue(decrypted_value)

        @property
        def python_type(self):
            """Return the Python type this is bound to (str)."""

            return self.impl.python_type

    class SQLAlchemyHashed(TypeDecorator):
        """Type adapter for SQLAlchemy to hash strings using Argon2."""

        impl = LargeBinary
        cache_ok = True

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def process_bind_param(self, value: str | bytes | None, dialect) -> bytes | None:
            """Hashes a string before binding it to the database."""

            if value is None:
                return None

            return hashing.argon2.argon2_hash_data(value)

        def process_literal_param(self, value: str | bytes | None, dialect) -> HashedValue | None:
            """Hashes a string for literal SQL expressions."""

            if value is None:
                return None

            processed = hashing.argon2.argon2_hash_data(value)

            return dialect.literal_processor(self.impl)(processed)

        def process_result_value(self, value: str | bytes | None, dialect) -> HashedValue | None:
            """Returns the hash value as-is from the database, wrapped as a HashableBinary."""

            if value is None:
                return None

            return HashedValue(value)

        @property
        def python_type(self):
            """Return the Python type this is bound to (str)."""
            return self.impl.python_type
