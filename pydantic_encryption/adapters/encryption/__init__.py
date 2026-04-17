from typing import TYPE_CHECKING

from pydantic_encryption.adapters.encryption import fernet

if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption import aws

__all__ = ["fernet", "aws"]


def __getattr__(name: str):
    if name == "aws":
        from pydantic_encryption.adapters.encryption import aws

        return aws

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
