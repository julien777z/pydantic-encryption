from typing import TYPE_CHECKING

from pydantic_encryption.config import settings
from pydantic_encryption.models import BaseModel, SecureModel
from pydantic_encryption.types import (
    Decrypt,
    DecryptedValue,
    Encrypt,
    EncryptedValue,
    EncryptionMethod,
    Hash,
    HashedValue,
)

if TYPE_CHECKING:
    from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted, SQLAlchemyHashed


def __getattr__(name: str):
    if name == "SQLAlchemyEncrypted":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted

        return SQLAlchemyEncrypted

    if name == "SQLAlchemyHashed":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyHashed

        return SQLAlchemyHashed

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "settings",
    "BaseModel",
    "SecureModel",
    "Encrypt",
    "Decrypt",
    "Hash",
    "EncryptionMethod",
    "EncryptedValue",
    "DecryptedValue",
    "HashedValue",
    "SQLAlchemyEncrypted",
    "SQLAlchemyHashed",
]
