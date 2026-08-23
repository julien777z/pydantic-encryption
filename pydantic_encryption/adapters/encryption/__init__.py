import importlib
from types import ModuleType
from typing import TYPE_CHECKING

from pydantic_encryption.adapters.encryption import fernet
from pydantic_encryption.adapters.registry import register_encryption_backend_lazy
from pydantic_encryption.types import EncryptionMethod

if TYPE_CHECKING:
    from pydantic_encryption.adapters.encryption import aws

__all__ = ["fernet", "aws"]


def load_aws_adapter() -> type:
    """Import the AWS adapter on first use so the optional extra stays optional."""

    from pydantic_encryption.adapters.encryption.aws import AWSAdapter

    return AWSAdapter


register_encryption_backend_lazy(EncryptionMethod.AWS, load_aws_adapter)


def __getattr__(name: str) -> ModuleType:
    """Import the AWS adapter module on first access so the optional extra stays optional."""

    if name == "aws":
        # import_module rather than a from-import: the latter consults this __getattr__ again
        # before falling back to the submodule, so it recurses instead of importing.
        return importlib.import_module(f"{__name__}.aws")

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
