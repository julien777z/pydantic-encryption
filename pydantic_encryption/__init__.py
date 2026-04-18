from typing import TYPE_CHECKING

from pydantic_encryption.adapters.base import BlindIndexAdapter, EncryptionAdapter, HashingAdapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.config import settings
from pydantic_encryption.models import BaseModel, SecureModel
from pydantic_encryption.types import (
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
    from pydantic_encryption.adapters.encryption.aws import AWSAdapter
    from pydantic_encryption.integrations.sqlalchemy import (
        SQLAlchemyBlindIndexValue,
        SQLAlchemyEncryptedValue,
        SQLAlchemyHashedValue,
        SQLAlchemyPGEncryptedArray,
    )
    from pydantic_encryption.integrations.sqlalchemy.bulk import DeferredDecryptMixin, async_decrypt_rows


def __getattr__(name: str):
    if name == "SQLAlchemyEncryptedValue":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncryptedValue

        return SQLAlchemyEncryptedValue

    if name == "SQLAlchemyPGEncryptedArray":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyPGEncryptedArray

        return SQLAlchemyPGEncryptedArray

    if name == "SQLAlchemyHashedValue":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyHashedValue

        return SQLAlchemyHashedValue

    if name == "SQLAlchemyBlindIndexValue":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyBlindIndexValue

        return SQLAlchemyBlindIndexValue

    if name == "AWSAdapter":
        from pydantic_encryption.adapters.encryption.aws import AWSAdapter

        return AWSAdapter

    if name == "async_decrypt_rows":
        from pydantic_encryption.integrations.sqlalchemy.bulk import async_decrypt_rows

        return async_decrypt_rows

    if name == "DeferredDecryptMixin":
        from pydantic_encryption.integrations.sqlalchemy.bulk import DeferredDecryptMixin

        return DeferredDecryptMixin

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
    # Adapter ABCs
    "EncryptionAdapter",
    "HashingAdapter",
    "BlindIndexAdapter",
    # Adapters (optional - lazy loaded)
    "AWSAdapter",
    # SQLAlchemy (optional - lazy loaded)
    "SQLAlchemyBlindIndexValue",
    "SQLAlchemyEncryptedValue",
    "SQLAlchemyPGEncryptedArray",
    "SQLAlchemyHashedValue",
    "async_decrypt_rows",
    "DeferredDecryptMixin",
]
