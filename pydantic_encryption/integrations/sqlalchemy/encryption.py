from typing import Any

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import Column, Table, event
from sqlalchemy.engine import Dialect
from sqlalchemy.types import ARRAY, LargeBinary, TypeDecorator

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.serialization import (
    EncryptableValue,
    decode_value,
    encode_value,
)
from pydantic_encryption.types import EncryptedValue, FieldBinding


def resolve_backend() -> Any:
    """Return the configured encryption backend, raising if ENCRYPTION_METHOD is unset."""

    method = settings.ENCRYPTION_METHOD

    if method is None:
        raise ValueError("ENCRYPTION_METHOD must be set to encrypt or decrypt values.")

    return get_encryption_backend(method)


def encrypt_cell(
    value: EncryptableValue | EncryptedValue | None, binding: FieldBinding | None
) -> EncryptedValue | None:
    """Encode + encrypt one value against its field binding, passing pre-encrypted values through."""

    if value is None:
        return None

    if isinstance(value, EncryptedValue):
        return value

    return resolve_backend().encrypt(encode_value(value, binding))


def decrypt_cell(value: str | bytes, binding: FieldBinding | None) -> EncryptableValue:
    """Decrypt one ciphertext and decode it, refusing one written for a different field."""

    return decode_value(resolve_backend().decrypt(value), binding)


class DeferrableEncryptedType(TypeDecorator):
    """Encrypted column type whose read path can hand back ciphertext for the batched drain."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.deferred = False
        self.binding: FieldBinding | None = None

    def bind_to(self, binding: FieldBinding) -> None:
        """Record the table and column whose values this type encrypts and decrypts."""

        self.binding = binding


def bind_encrypted_column(column: Column, table: Table) -> None:
    """Bind an encrypted column's ciphertexts to the table and column they are stored in."""

    if not isinstance(column.type, DeferrableEncryptedType):
        return

    # Copy so a type instance shared across columns is not stamped with one column's identity.
    column.type = column.type.copy()
    column.type.bind_to(FieldBinding(table=table.fullname, column=column.key))


event.listen(Column, "after_parent_attach", bind_encrypted_column)


class SQLAlchemyEncryptedValue(DeferrableEncryptedType):
    """SQLAlchemy column type that encrypts on write and decrypts on read."""

    impl = LargeBinary
    cache_ok = True

    def process_bind_param(self, value: EncryptableValue | None, dialect: Dialect) -> bytes | None:
        """Encrypt a value before binding it to the database."""

        return encrypt_cell(value, self.binding)

    # SQLAlchemy annotates process_literal_param as returning str, but TypeDecorator.literal_processor
    # feeds the result to the impl's literal processor, which for LargeBinary takes bytes.
    def process_literal_param(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, value: EncryptableValue | None, dialect: Dialect
    ) -> bytes | None:
        """Encrypt a value for literal SQL expressions."""

        return encrypt_cell(value, self.binding)

    def process_result_value(self, value: str | bytes | None, dialect: Dialect) -> EncryptableValue | None:
        """Decrypt a value after retrieving it from the database."""

        if value is None:
            return None

        if self.deferred:
            return EncryptedValue(value)

        return decrypt_cell(value, self.binding)

    @property
    def python_type(self) -> type[Any]:
        """Return the Python type this column is bound to."""

        return self.impl_instance.python_type


class SQLAlchemyPGEncryptedArray(DeferrableEncryptedType):
    """SQLAlchemy column type that encrypts each element of a PostgreSQL array."""

    impl = ARRAY(LargeBinary)
    cache_ok = True

    def process_bind_param(
        self, value: list[EncryptableValue | None] | None, dialect: Dialect
    ) -> list[EncryptedValue | None] | None:
        """Encrypt each element before binding to the database."""

        if value is None:
            return None

        return [encrypt_cell(element, self.binding) for element in value]

    # SQLAlchemy annotates process_literal_param as returning str, but TypeDecorator.literal_processor
    # feeds the result to the impl's literal processor, which for an array of LargeBinary takes a list.
    def process_literal_param(  # pyright: ignore[reportIncompatibleMethodOverride]
        self, value: list[EncryptableValue | None] | None, dialect: Dialect
    ) -> list[EncryptedValue | None] | None:
        """Encrypt each element for literal SQL expressions."""

        if value is None:
            return None

        return [encrypt_cell(element, self.binding) for element in value]

    def process_result_value(
        self, value: list[bytes | None] | None, dialect: Dialect
    ) -> list[EncryptableValue | None] | None:
        """Decrypt each element after retrieving the array from the database."""

        if value is None:
            return None

        if self.deferred:
            return [None if element is None else EncryptedValue(element) for element in value]

        return [None if element is None else decrypt_cell(element, self.binding) for element in value]

    @property
    def python_type(self) -> type[Any]:
        """Return the Python type this column is bound to."""

        return list
