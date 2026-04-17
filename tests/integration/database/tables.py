import uuid
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.integrations.sqlalchemy import (
    SQLAlchemyBlindIndexValue,
    SQLAlchemyEncryptedValue,
    SQLAlchemyHashedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.types import BlindIndexMethod

__all__ = ["Base", "User"]


class Base(DeclarativeBase):
    """Base model."""


class User(Base):
    """User model. Uses SQLAlchemyEncryptedValue and SQLAlchemyHashedValue types."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str | None] = mapped_column(String, default=None)
    email: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    password: Mapped[bytes] = mapped_column(SQLAlchemyHashedValue(), nullable=False)
    birth_date: Mapped[date | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    last_login: Mapped[datetime | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    age: Mapped[int | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    secret_data: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    is_active: Mapped[bool | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    balance: Mapped[float | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    salary: Mapped[Decimal | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    external_id: Mapped[uuid.UUID | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    login_time: Mapped[time | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    session_duration: Mapped[timedelta | None] = mapped_column(SQLAlchemyEncryptedValue(), default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), default=None)
    blind_index_email: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256), default=None
    )
    blind_index_email_argon2: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2), default=None
    )
