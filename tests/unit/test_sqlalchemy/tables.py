import uuid
from typing import Self

from sqlalchemy import Integer, String, Uuid, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.integrations.sqlalchemy.hashing import SQLAlchemyHashedValue
from pydantic_encryption.types import BlindIndexMethod
from tests.factories import User
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class AutoDecryptBase(DeclarativeBase):
    """Isolated declarative base for on-access decrypt session-level tests."""


class AutoDecryptUser(AutoDecryptBase, DeferredDecryptMixin):
    """Mapped class with a string-typed deferred encrypted column."""

    __tablename__ = "_auto_decrypt_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class AutoDecryptBlob(AutoDecryptBase, DeferredDecryptMixin):
    """Mapped class with a bytes-typed deferred encrypted column to test idempotency."""

    __tablename__ = "_auto_decrypt_blob"

    id: Mapped[int] = mapped_column(primary_key=True)
    payload: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class FinalizeBase(DeclarativeBase):
    """Isolated declarative base for finalize_sqlalchemy_session tests."""


class FinalizeUser(FinalizeBase, DeferredDecryptMixin):
    """Mapped class with one deferred encrypted column."""

    __tablename__ = "_finalize_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class OnAccessBase(DeclarativeBase):
    """Isolated declarative base for on-access decrypt unit tests."""


class OnAccessRow(OnAccessBase, DeferredDecryptMixin):
    """Two encrypted columns to verify per-column batching and scoped decrypts."""

    __tablename__ = "_on_access_row"

    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    last_name: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)

    @classmethod
    def from_user(cls, user: User) -> Self:
        """Build a row holding a user's names encrypted."""

        return cls(
            id=user.id,
            first_name=encrypt_through_column(cls.__table__.c.first_name, user.first_name),
            last_name=encrypt_through_column(cls.__table__.c.last_name, user.last_name),
        )


class OnAccessBytesRow(OnAccessBase, DeferredDecryptMixin):
    """Bytes-typed encrypted column for coverage of the same descriptor install path."""

    __tablename__ = "_on_access_bytes_row"

    id: Mapped[int] = mapped_column(primary_key=True)
    payload: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)

    @classmethod
    def from_user(cls, user: User) -> Self:
        """Build a row holding a user's payload encrypted."""

        return cls(id=user.id, payload=encrypt_through_column(cls.__table__.c.payload, user.payload))


class RowBoundBase(DeclarativeBase):
    """Isolated declarative base for the row-binding tests."""


class RowBoundRecord(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose encrypted column binds each row separately."""

    __tablename__ = "row_bound_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    label: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ExpressionKeyedRow(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose primary key defaults to an expression the database evaluates."""

    __tablename__ = "expression_keyed_rows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=func.gen_random_uuid())
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ServerKeyedRow(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose primary key does not exist until its insert returns."""

    __tablename__ = "server_keyed_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class UndeferredRow(RowBoundBase):
    """Mapped class that binds each row but never mixes in the deferred read path."""

    __tablename__ = "undeferred_rows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ColumnBoundRow(RowBoundBase, DeferredDecryptMixin):
    """Mapped class on the deferred read path whose encrypted column binds its column only."""

    __tablename__ = "column_bound_rows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    secret: Mapped[str | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class ContextBase(DeclarativeBase):
    """Isolated declarative base for the context-derivation tests."""


class SecretMixin:
    """Mixin whose encrypted columns are inherited by more than one table."""

    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    aliases: Mapped[list[str] | None] = mapped_column(
        SQLAlchemyPGEncryptedArray(), nullable=True, default=None
    )


class ContextUser(ContextBase, SecretMixin):
    """Table carrying the mixin column plus columns of its own."""

    __tablename__ = "context_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)
    envelope: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue("records.draft"), nullable=True, default=None
    )


class ContextRecord(ContextBase, SecretMixin):
    """Second table carrying the same mixin column."""

    __tablename__ = "context_records"

    id: Mapped[int] = mapped_column(primary_key=True)


class ArchivedEntry(ContextBase):
    """Table whose name is shared with another table in a different schema."""

    __tablename__ = "entries"
    __table_args__ = {"schema": "archive"}

    id: Mapped[int] = mapped_column(primary_key=True)
    note: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)


class PublicEntry(ContextBase):
    """Same table name in a second schema, whose columns must bind separately."""

    __tablename__ = "entries"
    __table_args__ = {"schema": "public"}

    id: Mapped[int] = mapped_column(primary_key=True)
    note: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class LiteralBase(DeclarativeBase):
    """Isolated declarative base for the literal-rendering tests."""


class LiteralRecord(LiteralBase):
    """Mapped class holding one column of every scalar binary column type."""

    __tablename__ = "literal_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    password: Mapped[bytes | None] = mapped_column(SQLAlchemyHashedValue(), nullable=True, default=None)
    email_index: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256), nullable=True, default=None
    )
