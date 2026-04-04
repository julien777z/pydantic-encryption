import uuid
from datetime import date, datetime, time, timedelta
from decimal import Decimal

from sqlmodel import Field, SQLModel

from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted, SQLAlchemyPGEncryptedArray, SQLAlchemyHashed

__all__ = ["Base", "User"]


class Base(SQLModel, table=False):
    """Base model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class User(Base, table=True):
    """User model. This model uses the `SQLAlchemyEncrypted` and `SQLAlchemyHashed` types."""

    __tablename__ = "users"

    username: str = Field(default=None)
    email: bytes = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    password: bytes = Field(
        sa_type=SQLAlchemyHashed(),
        nullable=False,
    )
    birth_date: date | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    last_login: datetime | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    age: int | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    secret_data: bytes | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    is_active: bool | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    balance: float | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    salary: Decimal | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    external_id: uuid.UUID | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    login_time: time | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    session_duration: timedelta | None = Field(
        default=None,
        sa_type=SQLAlchemyEncrypted(),
    )
    tags: list[str] | None = Field(
        default=None,
        sa_type=SQLAlchemyPGEncryptedArray(),
    )
