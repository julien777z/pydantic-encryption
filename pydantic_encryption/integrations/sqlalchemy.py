import base64
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Final
from uuid import UUID

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters import encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue, EncryptionMethod, HashedValue

# Type alias for all supported encrypted value types
EncryptableValue = str | bytes | bool | int | float | Decimal | UUID | date | datetime | time | timedelta

_VERSION_PREFIX: Final[str] = "v1"


class _TypePrefix(StrEnum):
    """Type prefixes for auto-detection of encrypted field types."""

    STR = "str"
    BYTES = "bytes"
    BOOL = "bool"
    INT = "int"
    FLOAT = "float"
    DECIMAL = "decimal"
    UUID = "uuid"
    DATE = "date"
    DATETIME = "datetime"
    TIME = "time"
    TIMEDELTA = "timedelta"


class SQLAlchemyEncrypted(TypeDecorator):
    """Type adapter for SQLAlchemy to encrypt and decrypt data using the specified encryption method."""

    impl = LargeBinary
    cache_ok = True

    def _serialize_value(self, value: EncryptableValue) -> str:
        """Serialize a value with version and type prefix for encryption.

        Format: "v1:type:data"
        """
        match value:
            case datetime():
                type_data = f"{_TypePrefix.DATETIME}:{value.isoformat()}"
            case date():
                type_data = f"{_TypePrefix.DATE}:{value.isoformat()}"
            case time():
                type_data = f"{_TypePrefix.TIME}:{value.isoformat()}"
            case timedelta():
                type_data = f"{_TypePrefix.TIMEDELTA}:{value.days},{value.seconds},{value.microseconds}"
            case bytes():
                type_data = f"{_TypePrefix.BYTES}:{base64.b64encode(value).decode('ascii')}"
            case bool():
                type_data = f"{_TypePrefix.BOOL}:{str(value).lower()}"
            case int():
                type_data = f"{_TypePrefix.INT}:{value}"
            case float():
                type_data = f"{_TypePrefix.FLOAT}:{value!r}"
            case Decimal():
                type_data = f"{_TypePrefix.DECIMAL}:{value}"
            case UUID():
                type_data = f"{_TypePrefix.UUID}:{value}"
            case _:
                type_data = f"{_TypePrefix.STR}:{value}"

        return f"{_VERSION_PREFIX}:{type_data}"

    def _deserialize_value(self, value: str) -> EncryptableValue:
        """Deserialize a decrypted value based on its version and type prefix.

        Format: "v1:type:data"
        If no version marker is present, returns the value as a string (legacy format).
        """
        version, _, remainder = value.partition(":")

        if not version:
            return value

        if version != _VERSION_PREFIX:
            raise RuntimeError("Unknown version")

        type_prefix, _, data = remainder.partition(":")

        match type_prefix:
            case _TypePrefix.DATETIME:
                return datetime.fromisoformat(data)
            case _TypePrefix.DATE:
                return date.fromisoformat(data)
            case _TypePrefix.TIME:
                return time.fromisoformat(data)
            case _TypePrefix.TIMEDELTA:
                parts = data.split(",")
                return timedelta(days=int(parts[0]), seconds=int(parts[1]), microseconds=int(parts[2]))
            case _TypePrefix.BYTES:
                return base64.b64decode(data)
            case _TypePrefix.BOOL:
                return data == "true"
            case _TypePrefix.INT:
                return int(data)
            case _TypePrefix.FLOAT:
                return float(data)
            case _TypePrefix.DECIMAL:
                return Decimal(data)
            case _TypePrefix.UUID:
                return UUID(data)
            case _TypePrefix.STR:
                return data
            case _:
                return data

    def _process_encrypt_value(self, value: EncryptableValue | None) -> EncryptedValue | None:
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

    def process_bind_param(self, value: EncryptableValue | None, dialect) -> bytes | None:
        """Encrypts data before binding it to the database."""

        return self._process_encrypt_value(value)

    def process_literal_param(self, value: EncryptableValue | None, dialect) -> bytes | None:
        """Encrypts data for literal SQL expressions."""

        return self._process_encrypt_value(value)

    def process_result_value(self, value: str | bytes | None, dialect) -> EncryptableValue | None:
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
