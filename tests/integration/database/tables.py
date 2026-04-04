import uuid
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from sqlmodel import Field, SQLModel

from pydantic_encryption.integrations.sqlalchemy import (
    SQLAlchemyBlindIndexValue,
    SQLAlchemyEncryptedValue,
    SQLAlchemyHashed,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.types import BlindIndexMethod

__all__ = ["Base", "User"]


class Base(SQLModel, table=False):
    """Base model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class User(Base, table=True):
    """User model. This model uses the `SQLAlchemyEncryptedValue` and `SQLAlchemyHashed` types."""

    __tablename__ = "users"

    username: str = Field(default=None)
    email: bytes = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    password: bytes = Field(
        sa_type=SQLAlchemyHashed(),
        nullable=False,
    )
    birth_date: date | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    last_login: datetime | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    age: int | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    secret_data: bytes | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    is_active: bool | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    balance: float | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    salary: Decimal | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    external_id: uuid.UUID | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    login_time: time | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    session_duration: timedelta | None = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedValue(),
    )
    tags: list[str] | None = Field(
        default=None,
        sa_type=SQLAlchemyPGEncryptedArray(),
    )
    blind_index_email: bytes | None = Field(
        default=None,
        sa_type=SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256),
    )
    blind_index_email_argon2: bytes | None = Field(
        default=None,
        sa_type=SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2),
    )
