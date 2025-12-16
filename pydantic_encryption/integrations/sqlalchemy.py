from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters import encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.types import DecryptedValue, EncryptedValue, EncryptionMethod, HashedValue


class SQLAlchemyEncrypted(TypeDecorator):
    """Type adapter for SQLAlchemy to encrypt and decrypt strings using the specified encryption method."""

    impl = LargeBinary
    cache_ok = True

    def _process_encrypt_value(self, value: str | bytes | None) -> EncryptedValue | None:
        if value is None:
            return None

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.FERNET:
                return encryption.fernet.FernetAdapter.encrypt(value)
            case EncryptionMethod.EVERVAULT:
                return encryption.evervault.EvervaultAdapter.encrypt(value)
            case EncryptionMethod.AWS:
                return encryption.aws.AWSAdapter.encrypt(value)
            case _:
                raise ValueError(f"Unknown encryption method: {settings.ENCRYPTION_METHOD}")

    def _process_decrypt_value(self, value: str | bytes | None) -> str | bytes | None:
        if value is None:
            return None

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.FERNET:
                return encryption.fernet.FernetAdapter.decrypt(value)
            case EncryptionMethod.EVERVAULT:
                return encryption.evervault.EvervaultAdapter.decrypt(value)
            case EncryptionMethod.AWS:
                return encryption.aws.AWSAdapter.decrypt(value)
            case _:
                raise ValueError(f"Unknown encryption method: {settings.ENCRYPTION_METHOD}")

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

    def process_bind_param(self, value: str | bytes | None, dialect) -> bytes | None:
        """Hashes a string before binding it to the database."""

        if value is None:
            return None

        return hashing.argon2.Argon2Adapter.hash(value)

    def process_literal_param(self, value: str | bytes | None, dialect) -> HashedValue | None:
        """Hashes a string for literal SQL expressions."""

        if value is None:
            return None

        processed = hashing.argon2.Argon2Adapter.hash(value)

        return dialect.literal_processor(self.impl)(processed)

    def process_result_value(self, value: str | bytes | None, dialect) -> HashedValue | None:
        """Returns the hash value as-is from the database, wrapped as a HashedValue."""

        if value is None:
            return None

        return HashedValue(value)

    @property
    def python_type(self):
        """Return the Python type this is bound to (str)."""

        return self.impl.python_type
