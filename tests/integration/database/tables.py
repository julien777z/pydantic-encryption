import uuid
from typing import Annotated
from sqlmodel import SQLModel, Field
from pydantic_encryption import (
    SQLAlchemyEncryptedString,
    SQLAlchemyHashedString,
    EncryptionMethod,
    Encrypt,
    Hash,
    BaseModel,
    sqlalchemy_table,
)


__all__ = ["Base", "User", "UserManaged"]


class Base(SQLModel, table=False):
    """Base model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)


class User(Base, table=True):
    """User model. This model uses the `SQLAlchemyEncryptedString` and `SQLAlchemyHashedString` types."""

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


@sqlalchemy_table(use_encryption_method=EncryptionMethod.FERNET)
class UserManaged(
    Base,
    BaseModel,
    table=True,
):
    """
    Managed User model. The `Encrypt` and `Hash` annotations are automatically converted to
    `SQLAlchemyEncryptedString` and `SQLAlchemyHashedString` types.
    """

    __tablename__ = "users_managed"

    username: str = Field(default=None)
    email: Annotated[str, Encrypt]
    password: Annotated[str, Hash]
