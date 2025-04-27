from cryptography.fernet import Fernet
from pydantic_encryption.config import settings


FERNET_CLIENT = None


def load_fernet_client() -> Fernet:
    global FERNET_CLIENT

    if not settings.ENCRYPTION_KEY:
        raise ValueError(
            "Fernet is not available. Please set the ENCRYPTION_KEY environment variable."
        )

    FERNET_CLIENT = FERNET_CLIENT or Fernet(settings.ENCRYPTION_KEY)

    return FERNET_CLIENT


def fernet_encrypt(plaintext: bytes) -> bytes:
    """Encrypt data using Fernet."""

    fernet_client = load_fernet_client()

    return fernet_client.encrypt(plaintext)


def fernet_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt data using Fernet."""

    fernet_client = load_fernet_client()

    return fernet_client.decrypt(ciphertext)
