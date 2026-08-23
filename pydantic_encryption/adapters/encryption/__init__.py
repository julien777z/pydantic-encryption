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


def __getattr__(name: str):
    if name == "aws":
        from pydantic_encryption.adapters.encryption import aws

        return aws

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
