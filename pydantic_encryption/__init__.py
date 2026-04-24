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
    EncryptedValueAccessError,
    EncryptionMethod,
    Hashed,
    HashedValue,
    is_encrypted,
)

if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption.aws import AWSAdapter
    from pydantic_encryption.integrations.sqlalchemy import (
        DeferredDecryptMixin,
        SQLAlchemyBlindIndexValue,
        SQLAlchemyEncryptedValue,
        SQLAlchemyHashedValue,
        SQLAlchemyPGEncryptedArray,
        decrypt_pending_fields,
        decrypt_rows,
        decrypt_values,
        finalize_session,
    )


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

    if name == "decrypt_rows":
        from pydantic_encryption.integrations.sqlalchemy import decrypt_rows

        return decrypt_rows

    if name == "decrypt_values":
        from pydantic_encryption.integrations.sqlalchemy import decrypt_values

        return decrypt_values

    if name == "decrypt_pending_fields":
        from pydantic_encryption.integrations.sqlalchemy import decrypt_pending_fields

        return decrypt_pending_fields

    if name == "finalize_session":
        from pydantic_encryption.integrations.sqlalchemy import finalize_session

        return finalize_session

    if name == "DeferredDecryptMixin":
        from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin

        return DeferredDecryptMixin

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "settings",
    "BaseModel",
    "SecureModel",
    "BlindIndex",
    "Encrypted",
    "Hashed",
    "BlindIndexMethod",
    "BlindIndexValue",
    "EncryptionMethod",
    "EncryptedValue",
    "EncryptedValueAccessError",
    "HashedValue",
    "is_encrypted",
    "FernetAdapter",
    "Argon2Adapter",
    "EncryptionAdapter",
    "HashingAdapter",
    "BlindIndexAdapter",
    "AWSAdapter",
    "SQLAlchemyBlindIndexValue",
    "SQLAlchemyEncryptedValue",
    "SQLAlchemyPGEncryptedArray",
    "SQLAlchemyHashedValue",
    "DeferredDecryptMixin",
    "decrypt_pending_fields",
    "decrypt_rows",
    "decrypt_values",
    "finalize_session",
]
