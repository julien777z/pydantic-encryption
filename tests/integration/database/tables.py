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

__all__ = ["Base", "User"]


class Base(DeclarativeBase):
    """Base model."""


class User(Base, DeferredDecryptMixin):
    """User model used across the sync and async integration tests.

    Inherits ``DeferredDecryptMixin`` so that encrypted columns are returned
    as ``EncryptedValue`` wrappers on read and decrypted on first attribute
    access. Under a sync ``Session`` the descriptor falls back to the
    synchronous decrypt path (no greenlet bridge available); under an
    ``AsyncSession`` it runs the batched ``asyncio.gather`` path used by
    ``finalize_sqlalchemy_session``.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    username: Mapped[str | None] = mapped_column(String, default=None)
    email: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue("users.email"), default=None)
    password: Mapped[bytes] = mapped_column(SQLAlchemyHashedValue(), nullable=False)
    birth_date: Mapped[date | None] = mapped_column(
        SQLAlchemyEncryptedValue("users.birth_date"), default=None
    )
    last_login: Mapped[datetime | None] = mapped_column(
        SQLAlchemyEncryptedValue("users.last_login"), default=None
    )
    age: Mapped[int | None] = mapped_column(SQLAlchemyEncryptedValue("users.age"), default=None)
    secret_data: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue("users.secret_data"), default=None
    )
    is_active: Mapped[bool | None] = mapped_column(SQLAlchemyEncryptedValue("users.is_active"), default=None)
    balance: Mapped[float | None] = mapped_column(SQLAlchemyEncryptedValue("users.balance"), default=None)
    salary: Mapped[Decimal | None] = mapped_column(SQLAlchemyEncryptedValue("users.salary"), default=None)
    external_id: Mapped[uuid.UUID | None] = mapped_column(
        SQLAlchemyEncryptedValue("users.external_id"), default=None
    )
    login_time: Mapped[time | None] = mapped_column(
        SQLAlchemyEncryptedValue("users.login_time"), default=None
    )
    session_duration: Mapped[timedelta | None] = mapped_column(
        SQLAlchemyEncryptedValue("users.session_duration"), default=None
    )
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray("users.tags"), default=None)
    blind_index_email: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256), default=None
    )
    blind_index_email_argon2: Mapped[bytes | None] = mapped_column(
        SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2), default=None
    )
