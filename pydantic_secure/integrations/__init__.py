from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic_secure.integrations import sqlalchemy

__all__ = ["sqlalchemy"]


def __getattr__(name: str):
    if name == "sqlalchemy":
        from pydantic_secure.integrations import sqlalchemy

        return sqlalchemy

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
