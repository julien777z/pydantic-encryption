from typing import Any

from pydantic_encryption.integrations.sqlalchemy.encryption import DeferrableEncryptedType
from pydantic_encryption.types import EncryptedValue, FieldBinding
from tests.dialects import TEST_DIALECT


def column_type(model: Any, column_key: str) -> DeferrableEncryptedType:
    """Return the encrypted column type a mapped class stores one of its columns through."""

    resolved = model.__table__.c[column_key].type

    assert isinstance(resolved, DeferrableEncryptedType)

    return resolved


def column_binding(model: Any, column_key: str) -> FieldBinding | None:
    """Return the field binding a mapped column stamps onto the ciphertexts it stores."""

    return column_type(model, column_key).binding


def encrypt_as_column(model: Any, column_key: str, value: Any) -> EncryptedValue:
    """Encrypt a value exactly as its own mapped column writes it, binding included."""

    ciphertext = column_type(model, column_key).process_bind_param(value, TEST_DIALECT)

    assert ciphertext is not None

    return EncryptedValue(ciphertext)
