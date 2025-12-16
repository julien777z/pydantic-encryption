from pydantic_encryption._lazy import LazyModule

sqlalchemy = LazyModule(
    "pydantic_encryption.integrations.sqlalchemy",
    required_extra="sqlalchemy",
)

__all__ = ["sqlalchemy"]
