import uuid
from pydantic_encryption import (
    SQLAlchemyEncryptedString,
    SQLAlchemyHashedString,
    EncryptionMethod,
)
from sqlmodel import SQLModel, Field


__all__ = ["Base", "User"]


class Base(SQLModel, table=False):
    """Base model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class User(Base, table=True):
    """User model."""

    __tablename__ = "users"

    username: str = Field(default=None)
    email: str = Field(
        default=None,
        sa_type=SQLAlchemyEncryptedString(encryption_method=EncryptionMethod.FERNET),
    )
    password: str = Field(
        sa_type=SQLAlchemyHashedString(),
        nullable=False,
    )
