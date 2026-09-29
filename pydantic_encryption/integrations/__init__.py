import importlib
from types import ModuleType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pydantic_encryption.integrations import sqlalchemy

__all__ = ["sqlalchemy"]


def __getattr__(name: str) -> ModuleType:
    """Lazy-load the SQLAlchemy integration so the package imports without the ``sqlalchemy`` extra."""

    if name == "sqlalchemy":
        return importlib.import_module("pydantic_encryption.integrations.sqlalchemy")

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
