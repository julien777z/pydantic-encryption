from pydantic_encryption._lazy import LazyModule

fernet = LazyModule("pydantic_encryption.adapters.encryption.fernet")
aws = LazyModule("pydantic_encryption.adapters.encryption.aws", required_extra="aws")
evervault = LazyModule("pydantic_encryption.adapters.encryption.evervault", required_extra="evervault")

__all__ = ["fernet", "aws", "evervault"]
