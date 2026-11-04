import importlib
from types import ModuleType
from typing import TYPE_CHECKING

from pydantic_encryption.adapters.encryption import fernet

if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption import aws

__all__ = ["fernet", "aws"]


def __getattr__(name: str) -> ModuleType:
    """Lazy-load the AWS adapter module so the package imports without the ``aws`` extra."""

    if name == "aws":
        return importlib.import_module("pydantic_encryption.adapters.encryption.aws")

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
