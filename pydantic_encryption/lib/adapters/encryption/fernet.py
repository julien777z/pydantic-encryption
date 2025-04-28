import base64
import struct
import time
from binascii import Error
from cryptography.fernet import Fernet
from pydantic_encryption.config import settings
from pydantic_encryption.models.string import EncryptableString

FERNET_CLIENT = None


def load_fernet_client() -> Fernet:
    global FERNET_CLIENT

    if not settings.ENCRYPTION_KEY:
        raise ValueError(
            "Fernet is not available. Please set the ENCRYPTION_KEY environment variable."
        )

    FERNET_CLIENT = FERNET_CLIENT or Fernet(settings.ENCRYPTION_KEY)

    return FERNET_CLIENT


def fernet_encrypt(plaintext: bytes | str | EncryptableString) -> EncryptableString:
    """Encrypt data using Fernet."""

    if getattr(plaintext, "is_encrypted", False):
        return plaintext

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    fernet_client = load_fernet_client()

    encrypted_value = EncryptableString(fernet_client.encrypt(plaintext))

    encrypted_value.is_encrypted = True

    return encrypted_value


def fernet_decrypt(ciphertext: str | bytes | EncryptableString) -> EncryptableString:
    """Decrypt data using Fernet."""

    fernet_client = load_fernet_client()

    if isinstance(ciphertext, bytes):
        ciphertext = ciphertext.decode("utf-8")

    if not getattr(ciphertext, "is_encrypted", False):
        return ciphertext

    decrypted_value = EncryptableString(fernet_client.decrypt(ciphertext))

    decrypted_value.is_encrypted = False

    return decrypted_value
