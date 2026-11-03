import uuid
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.integrations.sqlalchemy import (
    DeferredDecryptMixin,
    SQLAlchemyBlindIndexValue,
    SQLAlchemyEncryptedValue,
    SQLAlchemyHashedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.types import BlindIndexMethod

__all__ = ["Base", "Record"]


class Base(DeclarativeBase):
    """Base model."""


class Record(Base, DeferredDecryptMixin):
    """Record model with deferred encrypted columns, used across the sync and async integration tests."""

    __tablename__ = "records"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str | None] = mapped_column(String, default=None)
    note: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    password: Mapped[bytes] = mapped_column(SQLAlchemyHashedValue(), nullable=False)
    birth_date: Mapped[date | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    last_login: Mapped[datetime | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    age: Mapped[int | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    secret_data: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    is_active: Mapped[bool | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    balance: Mapped[float | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    quantity: Mapped[Decimal | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    external_id: Mapped[uuid.UUID | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    login_time: Mapped[time | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    session_duration: Mapped[timedelta | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), default=None)
    blind_index_note: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256), default=None
    )
    blind_index_note_argon2: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2), default=None
    )
