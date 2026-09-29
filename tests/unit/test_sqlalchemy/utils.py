from typing import TypeVar

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import KeyedColumnElement

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue

ColumnTypeT = TypeVar("ColumnTypeT")


class RecordingAsyncSession(AsyncSession):
    """AsyncSession whose transaction state is set by the test and whose commits are counted."""

    def __init__(self, in_transaction: bool) -> None:
        super().__init__()
        self.open_transaction = in_transaction
        self.commit_calls = 0

    def in_transaction(self) -> bool:
        """Return whether the test opened a transaction."""

        return self.open_transaction

    async def commit(self) -> None:
        """Count a commit and close the transaction."""

        self.commit_calls += 1
        self.open_transaction = False


def column_type_of(column: KeyedColumnElement[object], expected: type[ColumnTypeT]) -> ColumnTypeT:
    """Return a column's type, refusing a column whose type is of another class."""

    column_type = column.type
    if not isinstance(column_type, expected):
        raise TypeError(f"Column {column.key!r} is not a {expected.__name__} column.")

    return column_type


def encrypt_through_column(column: KeyedColumnElement[object], value: object) -> EncryptedValue:
    """Encrypt a value through a mapped column's own type so it carries that column's context."""

    ciphertext = column_type_of(column, SQLAlchemyEncryptedValue).encrypt_cell(value)
    if ciphertext is None:
        raise ValueError(f"Column {column.key!r} produced no ciphertext for {value!r}.")

    return ciphertext
