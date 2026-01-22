import base64
from datetime import date, datetime
from enum import StrEnum

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters import encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue, EncryptionMethod, HashedValue


class _TypePrefix(StrEnum):
    """Type prefixes for auto-detection of encrypted field types."""

    STR = "str"
    BYTES = "bytes"
    INT = "int"
    BOOL = "bool"
    DATE = "date"
    DATETIME = "datetime"


# Version marker to distinguish new serialized data from old data (pre-type-prefix format)
_SERIALIZATION_VERSION = "__v1__"


class SQLAlchemyEncrypted(TypeDecorator):
    """Type adapter for SQLAlchemy to encrypt and decrypt data using the specified encryption method."""

    impl = LargeBinary
    cache_ok = True

    def _serialize_value(self, value: str | bytes | int | bool | date | datetime) -> str:
        """Serialize a value with type prefix for encryption."""
        match value:
            case datetime():
                return f"{_SERIALIZATION_VERSION}{_TypePrefix.DATETIME}:{value.isoformat()}"
            case date():
                return f"{_SERIALIZATION_VERSION}{_TypePrefix.DATE}:{value.isoformat()}"
            case bytes():
                return f"{_SERIALIZATION_VERSION}{_TypePrefix.BYTES}:{base64.b64encode(value).decode('ascii')}"
            case bool():
                return f"{_SERIALIZATION_VERSION}{_TypePrefix.BOOL}:{value}"
            case int():
                return f"{_SERIALIZATION_VERSION}{_TypePrefix.INT}:{value}"
            case _:
                return f"{_SERIALIZATION_VERSION}{_TypePrefix.STR}:{value}"

    def _deserialize_value(self, value: str) -> str | bytes | int | bool | date | datetime:
        """Deserialize a decrypted value based on its type prefix."""
        # Check for version marker to distinguish new format from old (pre-type-prefix) data
        if not value.startswith(_SERIALIZATION_VERSION):
            # Old data without type prefixes - return as-is
            return value

        # Strip version prefix and parse type prefix
        versioned_data = value[len(_SERIALIZATION_VERSION):]
        prefix, _, data = versioned_data.partition(":")
        match prefix:
            case _TypePrefix.DATETIME:
                return datetime.fromisoformat(data)
            case _TypePrefix.DATE:
                return date.fromisoformat(data)
            case _TypePrefix.BYTES:
                return base64.b64decode(data)
            case _TypePrefix.BOOL:
                return data == "True"
            case _TypePrefix.INT:
                return int(data)
            case _TypePrefix.STR:
                return data
            case _:
                return value

    def _process_encrypt_value(self, value: str | bytes | int | bool | date | datetime | None) -> EncryptedValue | None:
        if value is None:
            return None

        serialized_value = self._serialize_value(value)

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.FERNET:
                return encryption.fernet.FernetAdapter.encrypt(serialized_value)
            case EncryptionMethod.EVERVAULT:
                return encryption.evervault.EvervaultAdapter.encrypt(serialized_value)
            case EncryptionMethod.AWS:
                return encryption.aws.AWSAdapter.encrypt(serialized_value)
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

    def process_bind_param(
        self, value: str | bytes | int | bool | date | datetime | None, dialect
    ) -> bytes | None:
        """Encrypts data before binding it to the database."""

        return self._process_encrypt_value(value)

    def process_literal_param(
        self, value: str | bytes | int | bool | date | datetime | None, dialect
    ) -> bytes | None:
        """Encrypts data for literal SQL expressions."""

        return self._process_encrypt_value(value)

    def process_result_value(
        self, value: str | bytes | None, dialect
    ) -> str | bytes | int | bool | date | datetime | None:
        """Decrypts data after retrieving it from the database."""

        if value is None:
            return None

        decrypted_value = self._process_decrypt_value(value)

        return self._deserialize_value(decrypted_value)

    @property
    def python_type(self):
        """Return the Python type this is bound to."""

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
