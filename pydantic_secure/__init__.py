from typing import TYPE_CHECKING

from pydantic_secure.adapters.base import AsyncBlindIndexAdapter, AsyncEncryptionAdapter, AsyncHashingAdapter
from pydantic_secure.adapters.encryption.fernet import FernetAdapter
from pydantic_secure.adapters.hashing.argon2 import Argon2Adapter
from pydantic_secure.config import settings
from pydantic_secure.models import BaseModel, SecureModel
from pydantic_secure.types import (
    BlindIndex,
    BlindIndexMethod,
    BlindIndexValue,
    Encrypted,
    EncryptedValue,
    EncryptionMethod,
    Hashed,
    HashedValue,
)

# Lazy loading for optional dependencies
if TYPE_CHECKING:
    from pydantic_secure.adapters.encryption.aws import AWSAdapter
    from pydantic_secure.integrations.sqlalchemy import (
        SQLAlchemyBlindIndexValue,
        SQLAlchemyEncryptedValue,
        SQLAlchemyHashedValue,
        SQLAlchemyPGEncryptedArray,
    )


def __getattr__(name: str):
    if name == "SQLAlchemyEncryptedValue":
        from pydantic_secure.integrations.sqlalchemy import SQLAlchemyEncryptedValue

        return SQLAlchemyEncryptedValue

    if name == "SQLAlchemyPGEncryptedArray":
        from pydantic_secure.integrations.sqlalchemy import SQLAlchemyPGEncryptedArray

        return SQLAlchemyPGEncryptedArray

    if name == "SQLAlchemyHashedValue":
        from pydantic_secure.integrations.sqlalchemy import SQLAlchemyHashedValue

        return SQLAlchemyHashedValue

    if name == "SQLAlchemyBlindIndexValue":
        from pydantic_secure.integrations.sqlalchemy import SQLAlchemyBlindIndexValue

        return SQLAlchemyBlindIndexValue

    if name == "AWSAdapter":
        from pydantic_secure.adapters.encryption.aws import AWSAdapter

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
    "Encrypted",
    "Hashed",
    # Types
    "BlindIndexMethod",
    "BlindIndexValue",
    "EncryptionMethod",
    "EncryptedValue",
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
    "SQLAlchemyHashedValue",
]
