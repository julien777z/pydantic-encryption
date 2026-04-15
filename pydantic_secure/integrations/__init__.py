from pydantic_secure._lazy import LazyModule

sqlalchemy = LazyModule(
    "pydantic_secure.integrations.sqlalchemy",
    required_extra="sqlalchemy",
)

__all__ = ["sqlalchemy"]
