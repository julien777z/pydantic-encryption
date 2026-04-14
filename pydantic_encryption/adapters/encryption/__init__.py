from typing import TYPE_CHECKING

from pydantic_encryption.adapters.encryption import fernet

if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption import aws
else:
    from pydantic_encryption._lazy import LazyModule

    aws = LazyModule("pydantic_encryption.adapters.encryption.aws", required_extra="aws")

__all__ = ["fernet", "aws"]
