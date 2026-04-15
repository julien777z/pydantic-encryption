import base64
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

from pydantic_secure._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import ARRAY, LargeBinary, TypeDecorator

from pydantic_secure.adapters.registry import get_encryption_backend
from pydantic_secure.config import settings
from pydantic_secure.integrations.sqlalchemy.shared import EncryptableValue, TypePrefix, VERSION_PREFIX
from pydantic_secure.types import EncryptedValue


class SQLAlchemyEncryptedValue(TypeDecorator):
    """Type adapter for SQLAlchemy to encrypt and decrypt data using the specified encryption method."""

    impl = LargeBinary
    cache_ok = True

    def _serialize_value(self, value: EncryptableValue) -> str:
        """Serialize a value with version and type prefix for encryption."""
        match value:
            case datetime():
                type_data = f"{TypePrefix.DATETIME}:{value.isoformat()}"
            case date():
                type_data = f"{TypePrefix.DATE}:{value.isoformat()}"
            case time():
                type_data = f"{TypePrefix.TIME}:{value.isoformat()}"
            case timedelta():
                type_data = f"{TypePrefix.TIMEDELTA}:{value.days},{value.seconds},{value.microseconds}"
            case bytes():
                type_data = f"{TypePrefix.BYTES}:{base64.b64encode(value).decode('ascii')}"
            case bool():
                type_data = f"{TypePrefix.BOOL}:{str(value).lower()}"
            case int():
                type_data = f"{TypePrefix.INT}:{value}"
            case float():
                type_data = f"{TypePrefix.FLOAT}:{value!r}"
            case Decimal():
                type_data = f"{TypePrefix.DECIMAL}:{value}"
            case UUID():
                type_data = f"{TypePrefix.UUID}:{value}"
            case _:
                type_data = f"{TypePrefix.STR}:{value}"

        return f"{VERSION_PREFIX}:{type_data}"

    def _deserialize_value(self, value: str) -> EncryptableValue:
        """Deserialize a decrypted value based on its version and type prefix."""
        version, _, remainder = value.partition(":")

        if not version:
            return value

        if version != VERSION_PREFIX:
            raise RuntimeError("Unknown version")

        type_prefix, _, data = remainder.partition(":")

        match type_prefix:
            case TypePrefix.DATETIME:
                return datetime.fromisoformat(data)
            case TypePrefix.DATE:
                return date.fromisoformat(data)
            case TypePrefix.TIME:
                return time.fromisoformat(data)
            case TypePrefix.TIMEDELTA:
                parts = data.split(",")
                return timedelta(days=int(parts[0]), seconds=int(parts[1]), microseconds=int(parts[2]))
            case TypePrefix.BYTES:
                return base64.b64decode(data)
            case TypePrefix.BOOL:
                return data == "true"
            case TypePrefix.INT:
                return int(data)
            case TypePrefix.FLOAT:
                return float(data)
            case TypePrefix.DECIMAL:
                return Decimal(data)
            case TypePrefix.UUID:
                return UUID(data)
            case TypePrefix.STR:
                return data
            case _:
                return data

    def _process_encrypt_value(self, value: EncryptableValue | EncryptedValue | None) -> EncryptedValue | None:
        if value is None:
            return None

        if isinstance(value, EncryptedValue):
            return value

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use SQLAlchemyEncryptedValue.")

        serialized_value = self._serialize_value(value)
        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
        return backend.encrypt(serialized_value)

    def _process_decrypt_value(self, value: str | bytes | None) -> str | bytes | None:
        if value is None:
            return None

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use SQLAlchemyEncryptedValue.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
        return backend.decrypt(value)

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
    """Type adapter for SQLAlchemy to encrypt and decrypt arrays."""

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
