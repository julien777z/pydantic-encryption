from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import ARRAY, LargeBinary, TypeDecorator

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.serialization import (
    EncryptableValue,
    decode_value,
    encode_value,
)
from pydantic_encryption.types import EncryptedValue


class SQLAlchemyEncryptedValue(TypeDecorator):
    """SQLAlchemy column type that encrypts on write and decrypts on read."""

    impl = LargeBinary
    cache_ok = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._deferred = False

    def _encrypt_cell(self, value: EncryptableValue | EncryptedValue | None) -> EncryptedValue | None:
        """Encode + encrypt a single value, passing pre-encrypted values through."""

        if value is None:
            return None

        if isinstance(value, EncryptedValue):
            return value

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use SQLAlchemyEncryptedValue.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
        serialized = encode_value(value)

        return run_async_or_sync(backend.async_encrypt, backend.encrypt, serialized)

    def _decrypt_cell(self, value: str | bytes | None) -> str | bytes | None:
        """Decrypt a single ciphertext; callers are responsible for decoding."""

        if value is None:
            return None

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use SQLAlchemyEncryptedValue.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)

        return run_async_or_sync(backend.async_decrypt, backend.decrypt, value)

    def process_bind_param(self, value: EncryptableValue | None, dialect) -> bytes | None:
        """Encrypt a value before binding it to the database."""

        return self._encrypt_cell(value)

    def process_literal_param(self, value: EncryptableValue | None, dialect) -> bytes | None:
        """Encrypt a value for literal SQL expressions."""

        return self._encrypt_cell(value)

    def process_result_value(self, value: str | bytes | None, dialect) -> EncryptableValue | None:
        """Decrypt a value after retrieving it from the database."""

        if value is None:
            return None

        if self._deferred:
            return EncryptedValue(value)

        return decode_value(self._decrypt_cell(value))

    @property
    def python_type(self):
        """Return the Python type this column is bound to."""

        return self.impl.python_type


class SQLAlchemyPGEncryptedArray(TypeDecorator):
    """SQLAlchemy column type that encrypts each element of a PostgreSQL array."""

    impl = ARRAY(LargeBinary)
    cache_ok = True

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._element_type = SQLAlchemyEncryptedValue()

    def process_bind_param(self, value: list[EncryptableValue] | None, dialect) -> list[bytes] | None:
        """Encrypt each element before binding to the database."""

        if value is None:
            return None

        return [self._element_type._encrypt_cell(element) for element in value]

    def process_literal_param(self, value: list[EncryptableValue] | None, dialect) -> list[bytes] | None:
        """Encrypt each element for literal SQL expressions."""

        if value is None:
            return None

        return [self._element_type._encrypt_cell(element) for element in value]

    def process_result_value(self, value: list[bytes] | None, dialect) -> list[EncryptableValue] | None:
        """Decrypt each element after retrieving the array from the database."""

        if value is None:
            return None

        return [
            None if element is None else decode_value(self._element_type._decrypt_cell(element))
            for element in value
        ]

    @property
    def python_type(self):
        """Return the Python type this column is bound to."""

        return list
