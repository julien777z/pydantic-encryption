import base64
import hashlib
import hmac
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Final
from uuid import UUID

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import ARRAY, LargeBinary, TypeDecorator

from pydantic_encryption.adapters import encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue, EncryptedValue, EncryptionMethod, HashedValue

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


class SQLAlchemyEncryptedValue(TypeDecorator):
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


class SQLAlchemyPGEncryptedArray(TypeDecorator):
    """Type adapter for SQLAlchemy to encrypt and decrypt arrays using the specified encryption method.

    Each element in the array is individually encrypted/decrypted. This type uses PostgreSQL's
    native ARRAY(LargeBinary) column type, so it requires a PostgreSQL backend.
    """

    impl = ARRAY(LargeBinary)
    cache_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._element_type = SQLAlchemyEncryptedValue()

    def process_bind_param(self, value: list[EncryptableValue] | None, dialect) -> list[bytes] | None:
        """Encrypts each element in the array before binding to the database."""

        if value is None:
            return None

        return [self._element_type._process_encrypt_value(element) for element in value]

    def process_literal_param(self, value: list[EncryptableValue] | None, dialect) -> list[bytes] | None:
        """Encrypts each element in the array for literal SQL expressions."""

        if value is None:
            return None

        return [self._element_type._process_encrypt_value(element) for element in value]

    def process_result_value(self, value: list[bytes] | None, dialect) -> list[EncryptableValue] | None:
        """Decrypts each element in the array after retrieving from the database."""

        if value is None:
            return None

        result = []
        for element in value:
            if element is None:
                result.append(None)
            else:
                decrypted = self._element_type._process_decrypt_value(element)
                result.append(self._element_type._deserialize_value(decrypted))
        return result

    @property
    def python_type(self):
        """Return the Python type this is bound to."""

        return list


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


class SQLAlchemyBlindIndexValue(TypeDecorator):
    """Type adapter for SQLAlchemy to create deterministic blind indexes.

    Blind indexes enable equality searches on encrypted columns by storing a
    keyed hash of the plaintext alongside the ciphertext. The hash is deterministic
    (same input always produces the same output) but requires the secret key to compute.

    Supports HMAC-SHA256 and Argon2 hashing methods. Requires
    BLIND_INDEX_SECRET_KEY to be set in configuration.
    """

    impl = LargeBinary
    cache_ok = True

    def __init__(self, method: BlindIndexMethod):
        super().__init__()
        self.method = method

    def _get_key_bytes(self) -> bytes:
        if settings.BLIND_INDEX_SECRET_KEY is None:
            raise ValueError(
                "BLIND_INDEX_SECRET_KEY must be set to use SQLAlchemyBlindIndexValue. "
                "Set it via environment variable or .env file."
            )
        return settings.BLIND_INDEX_SECRET_KEY.encode("utf-8")

    def _compute_blind_index(self, value: str | bytes) -> bytes:
        """Compute a deterministic blind index for the given value."""

        key = self._get_key_bytes()

        if isinstance(value, str):
            value = value.encode("utf-8")

        match self.method:
            case BlindIndexMethod.HMAC_SHA256:
                return hmac.new(key, value, hashlib.sha256).digest()
            case BlindIndexMethod.ARGON2:
                from argon2.low_level import Type as Argon2Type
                from argon2.low_level import hash_secret_raw

                salt = hashlib.sha256(key).digest()[:16]
                return hash_secret_raw(
                    secret=value,
                    salt=salt,
                    time_cost=3,
                    memory_cost=65536,
                    parallelism=1,
                    hash_len=32,
                    type=Argon2Type.ID,
                )
            case _:
                raise ValueError(f"Unknown blind index method: {self.method}")

    def process_bind_param(self, value: str | bytes | None, dialect) -> bytes | None:
        """Computes the blind index before binding to the database."""

        if value is None:
            return None

        return self._compute_blind_index(value)

    def process_literal_param(self, value: str | bytes | None, dialect) -> bytes | None:
        """Computes the blind index for literal SQL expressions."""

        if value is None:
            return None

        return self._compute_blind_index(value)

    def process_result_value(self, value: bytes | None, dialect) -> BlindIndexValue | None:
        """Returns the blind index value as-is from the database."""

        if value is None:
            return None

        return BlindIndexValue(value)

    @property
    def python_type(self):
        """Return the Python type this is bound to."""

        return self.impl.python_type
