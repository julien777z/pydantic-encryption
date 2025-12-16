from typing import TYPE_CHECKING

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
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

# Lazy loading for optional dependencies
if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption.aws import AWSAdapter
    from pydantic_encryption.adapters.encryption.evervault import EvervaultAdapter
    from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted, SQLAlchemyHashed


def __getattr__(name: str):
    if name == "SQLAlchemyEncrypted":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted

        return SQLAlchemyEncrypted

    if name == "SQLAlchemyHashed":
        from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyHashed

        return SQLAlchemyHashed

    if name == "AWSAdapter":
        from pydantic_encryption.adapters.encryption.aws import AWSAdapter

        return AWSAdapter

    if name == "EvervaultAdapter":
        from pydantic_encryption.adapters.encryption.evervault import EvervaultAdapter

        return EvervaultAdapter

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Config
    "settings",
    # Models
    "BaseModel",
    "SecureModel",
    # Annotations
    "Encrypt",
    "Decrypt",
    "Hash",
    # Types
    "EncryptionMethod",
    "EncryptedValue",
    "DecryptedValue",
    "HashedValue",
    # Adapters (default)
    "FernetAdapter",
    "Argon2Adapter",
    # Adapters (optional - lazy loaded)
    "AWSAdapter",
    "EvervaultAdapter",
    # SQLAlchemy (optional - lazy loaded)
    "SQLAlchemyEncrypted",
    "SQLAlchemyHashed",
]
