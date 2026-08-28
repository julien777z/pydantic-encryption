from typing import Any

from sqlalchemy.sql.elements import KeyedColumnElement

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


def encrypt_through_column(column: KeyedColumnElement[Any], value: Any) -> EncryptedValue:
    """Encrypt a value through a mapped column's own type so it carries that column's context."""

    column_type = column.type
    if not isinstance(column_type, SQLAlchemyEncryptedValue):
        raise TypeError(f"Column {column.key!r} does not encrypt its values.")

    ciphertext = column_type.encrypt_cell(value)
    if ciphertext is None:
        raise ValueError(f"Column {column.key!r} produced no ciphertext for {value!r}.")

    return ciphertext
