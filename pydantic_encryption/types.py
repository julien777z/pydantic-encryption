from enum import Enum

from pydantic_encryption.normalization import validate_normalization_flags


class Encrypted:
    """Annotation to mark fields for encryption."""


class Hashed:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Supported encryption methods."""

    FERNET = "fernet"
    AWS = "aws"


class BlindIndexMethod(Enum):
    """Supported blind index hashing methods."""

    HMAC_SHA256 = "hmac-sha256"
    ARGON2 = "argon2"


class EncryptedValueAccessError(RuntimeError):
    """Raised when an encrypted ciphertext is coerced to str before decryption."""


class _TaggedBytes(bytes):
    """Bytes subclass that UTF-8-encodes ``str`` inputs."""

    def __new__(cls, value: str | bytes):
        if isinstance(value, str):
            value = value.encode("utf-8")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"<{type(self).__name__}: {len(self)} bytes>"


class EncryptedValue(_TaggedBytes):
    """Bytes subclass representing an encrypted ciphertext; ``str()`` raises to flag accidental coercion."""

    def __str__(self) -> str:
        raise EncryptedValueAccessError(
            "Encrypted value coerced to str before decryption. Read the attribute via the ORM "
            "instance to trigger on-access decrypt, or call "
            "`await decrypt_pending_fields(session)` to materialize loaded rows. "
            "Use `bytes(value)` if you explicitly need the raw ciphertext."
        )


class HashedValue(_TaggedBytes):
    """Bytes subclass representing a hashed value."""


class BlindIndexValue(_TaggedBytes):
    """Bytes subclass representing a blind index value."""


class BlindIndex:
    """Annotation to mark fields for blind indexing."""

    def __init__(
        self,
        method: BlindIndexMethod,
        *,
        strip_whitespace: bool = False,
        strip_non_characters: bool = False,
        strip_non_digits: bool = False,
        normalize_to_lowercase: bool = False,
        normalize_to_uppercase: bool = False,
    ):
        validate_normalization_flags(
            strip_non_characters=strip_non_characters,
            strip_non_digits=strip_non_digits,
            normalize_to_lowercase=normalize_to_lowercase,
            normalize_to_uppercase=normalize_to_uppercase,
        )

        self.method = method
        self.strip_whitespace = strip_whitespace
        self.strip_non_characters = strip_non_characters
        self.strip_non_digits = strip_non_digits
        self.normalize_to_lowercase = normalize_to_lowercase
        self.normalize_to_uppercase = normalize_to_uppercase


def is_encrypted(value: object) -> bool:
    """Return True if the value is a still-encrypted ciphertext wrapper."""

    return isinstance(value, EncryptedValue)


__all__ = [
    "Encrypted",
    "Hashed",
    "EncryptionMethod",
    "EncryptedValue",
    "EncryptedValueAccessError",
    "HashedValue",
    "BlindIndex",
    "BlindIndexMethod",
    "BlindIndexValue",
    "is_encrypted",
]
