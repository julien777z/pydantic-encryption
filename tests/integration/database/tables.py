import uuid
from sqlmodel import SQLModel, Field
from pydantic_encryption import (
    SQLAlchemyEncrypted,
    SQLAlchemyHashed,
    EncryptionMethod,
)


__all__ = ["Base", "User"]


class Base(SQLModel, table=False):
    """Base model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class User(Base, table=True):
    """User model. This model uses the `SQLAlchemyEncryptedString` and `SQLAlchemyHashedString` types."""

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
