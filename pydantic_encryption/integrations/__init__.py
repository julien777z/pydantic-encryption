import importlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic_encryption.integrations import sqlalchemy

__all__ = ["sqlalchemy"]


def __getattr__(name: str):
    if name == "sqlalchemy":
        return importlib.import_module("pydantic_encryption.integrations.sqlalchemy")

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
