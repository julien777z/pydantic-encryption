from enum import Enum
from typing import Any, Callable, Optional, Type, get_origin, get_args, Annotated
from pydantic import BeforeValidator


class Encrypt:
    """Annotation to mark fields for encryption."""


def decrypt_bytes_to_str(v: bytes | str) -> str:
    if isinstance(v, bytes):
        return v.decode("utf-8")

    return v


Decrypt = Annotated[str, BeforeValidator(decrypt_bytes_to_str)]


class Hash:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Enum for encryption methods."""

    FERNET = "fernet"
    EVERVAULT = "evervault"
    AWS = "aws"
