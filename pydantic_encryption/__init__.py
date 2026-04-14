from typing import TYPE_CHECKING

from pydantic_encryption.adapters.base import AsyncBlindIndexAdapter, AsyncEncryptionAdapter, AsyncHashingAdapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.config import settings
from pydantic_encryption.models import BaseModel, SecureModel
from pydantic_encryption.types import (
    BlindIndex,
    BlindIndexMethod,
    BlindIndexValue,
    Decrypt,
    DecryptedValue,
    Encrypt,
    EncryptedValue,
    EncryptionMethod,
    Hash,
    HashedValue,
)

# Lazy loading for optional dependencies
if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption.aws import AWSAdapter
    from pydantic_encryption.integrations.sqlalchemy import (
        SQLAlchemyBlindIndexValue,
        SQLAlchemyEncryptedValue,
        SQLAlchemyHashed,
        SQLAlchemyPGEncryptedArray,
    )


def __getattr__(name: str):
    if name == "SQLAlchemyEncryptedValue":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncryptedValue

        return SQLAlchemyEncryptedValue

    if name == "SQLAlchemyPGEncryptedArray":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyPGEncryptedArray

        return SQLAlchemyPGEncryptedArray

    if name == "SQLAlchemyHashed":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyHashed

        return SQLAlchemyHashed

    if name == "SQLAlchemyBlindIndexValue":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyBlindIndexValue

        return SQLAlchemyBlindIndexValue

    if name == "AWSAdapter":
        from pydantic_encryption.adapters.encryption.aws import AWSAdapter

        return AWSAdapter

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Config
    "settings",
    # Models
    "BaseModel",
    "SecureModel",
    # Annotations
    "BlindIndex",
    "Encrypt",
    "Decrypt",
    "Hash",
    # Types
    "BlindIndexMethod",
    "BlindIndexValue",
    "EncryptionMethod",
    "EncryptedValue",
    "DecryptedValue",
    "HashedValue",
    # Adapters (default)
    "FernetAdapter",
    "Argon2Adapter",
    # Async adapter ABCs
    "AsyncEncryptionAdapter",
    "AsyncHashingAdapter",
    "AsyncBlindIndexAdapter",
    # Adapters (optional - lazy loaded)
    "AWSAdapter",
    # SQLAlchemy (optional - lazy loaded)
    "SQLAlchemyBlindIndexValue",
    "SQLAlchemyEncryptedValue",
    "SQLAlchemyPGEncryptedArray",
    "SQLAlchemyHashed",
]
