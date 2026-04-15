from typing import TYPE_CHECKING

from pydantic_secure.adapters.encryption import fernet

if TYPE_CHECKING:
    from pydantic_secure.adapters.encryption import aws
else:
    from pydantic_secure._lazy import LazyModule

    aws = LazyModule("pydantic_secure.adapters.encryption.aws", required_extra="aws")

__all__ = ["fernet", "aws"]
