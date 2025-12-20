from typing import TYPE_CHECKING

from pydantic_encryption.adapters.encryption import fernet

if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption import aws, evervault
else:
    from pydantic_encryption._lazy import LazyModule

    aws = LazyModule("pydantic_encryption.adapters.encryption.aws", required_extra="aws")
    evervault = LazyModule("pydantic_encryption.adapters.encryption.evervault", required_extra="evervault")

__all__ = ["fernet", "aws", "evervault"]
