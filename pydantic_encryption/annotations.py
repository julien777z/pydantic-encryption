from enum import Enum


class Encrypt:
    """Annotation to mark fields for encryption."""


class Decrypt:
    """Annotation to mark fields for decryption."""


class Hash:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Enum for encryption methods."""

    FERNET = "fernet"
    EVERVAULT = "evervault"
