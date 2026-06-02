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
        finalize_sqlalchemy_session,
    )


LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "AWSAdapter": ("pydantic_encryption.adapters.encryption.aws", "AWSAdapter"),
    "DeferredDecryptMixin": ("pydantic_encryption.integrations.sqlalchemy", "DeferredDecryptMixin"),
    "SQLAlchemyBlindIndexValue": ("pydantic_encryption.integrations.sqlalchemy", "SQLAlchemyBlindIndexValue"),
    "SQLAlchemyEncryptedValue": ("pydantic_encryption.integrations.sqlalchemy", "SQLAlchemyEncryptedValue"),
    "SQLAlchemyHashedValue": ("pydantic_encryption.integrations.sqlalchemy", "SQLAlchemyHashedValue"),
    "SQLAlchemyPGEncryptedArray": ("pydantic_encryption.integrations.sqlalchemy", "SQLAlchemyPGEncryptedArray"),
    "decrypt_pending_fields": ("pydantic_encryption.integrations.sqlalchemy", "decrypt_pending_fields"),
    "decrypt_rows": ("pydantic_encryption.integrations.sqlalchemy", "decrypt_rows"),
    "decrypt_values": ("pydantic_encryption.integrations.sqlalchemy", "decrypt_values"),
    "finalize_sqlalchemy_session": (
        "pydantic_encryption.integrations.sqlalchemy",
        "finalize_sqlalchemy_session",
    ),
}


def __getattr__(name: str):
    """Lazy-load optional symbols (SQLAlchemy / AWS) so the package imports without those extras."""

    target = LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attr = target
    import importlib

    return getattr(importlib.import_module(module_name), attr)


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
    "finalize_sqlalchemy_session",
]
