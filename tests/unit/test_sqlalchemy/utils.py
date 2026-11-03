from collections import defaultdict
from typing import TypeVar
from weakref import WeakSet

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import KeyedColumnElement

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY, read_raw_cell
from pydantic_encryption.serialization import EncryptableValue
from pydantic_encryption.types import EncryptedValue

ColumnTypeT = TypeVar("ColumnTypeT")


class RecordingAsyncSession(AsyncSession):
    """AsyncSession holding pending rows, with a transaction state the test sets and counted commits."""

    def __init__(
        self, in_transaction: bool, pending: list[object], watched: tuple[object, str] | None = None
    ) -> None:
        super().__init__()

        bucket: defaultdict[type[object], WeakSet[object]] = defaultdict(WeakSet)

        for row in pending:
            bucket[type(row)].add(row)

        self.info[PENDING_DECRYPT_KEY] = bucket
        self.open_transaction = in_transaction
        self.commit_calls = 0
        self.watched = watched
        self.watched_at_commit: object = None

    def in_transaction(self) -> bool:
        """Return whether the test opened a transaction."""

        return self.open_transaction

    async def commit(self) -> None:
        """Count a commit, record the watched cell as it stands, and close the transaction."""

        if self.watched is not None:
            self.watched_at_commit = read_raw_cell(*self.watched)

        self.commit_calls += 1
        self.open_transaction = False


def column_type_of(column: KeyedColumnElement[object], expected: type[ColumnTypeT]) -> ColumnTypeT:
    """Return a column's type, refusing a column whose type is of another class."""

    column_type = column.type
    if not isinstance(column_type, expected):
        raise TypeError(f"Column {column.key!r} is not a {expected.__name__} column.")

    return column_type


def encrypt_through_column(column: KeyedColumnElement[object], value: EncryptableValue) -> EncryptedValue:
    """Encrypt a value through a mapped column's own type so it carries that column's context."""

    return column_type_of(column, SQLAlchemyEncryptedValue).encrypt_cell(value)
