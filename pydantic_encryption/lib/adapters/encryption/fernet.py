try:
    from cryptography.fernet import Fernet
except ImportError:
    pass
else:
    FERNET_CLIENT = None

from pydantic_encryption.config import settings
from pydantic_encryption.annotations import EncryptionMethod
from pydantic_encryption.models.encryptable import EncryptedValue, DecryptedValue

if settings.ENCRYPTION_METHOD == EncryptionMethod.FERNET:
    if not settings.ENCRYPTION_KEY:
        raise ValueError(
            "Fernet is not available. Please set the ENCRYPTION_KEY environment variable."
        )

    FERNET_CLIENT = FERNET_CLIENT or Fernet(settings.ENCRYPTION_KEY)


def fernet_encrypt(
    plaintext: bytes | str | EncryptedValue,
) -> EncryptedValue:
    """Encrypt data using Fernet."""

    if isinstance(plaintext, EncryptedValue):
        return plaintext

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    encrypted_value = EncryptedValue(FERNET_CLIENT.encrypt(plaintext))

    return encrypted_value


def fernet_decrypt(
    ciphertext: str | bytes | EncryptedValue,
) -> DecryptedValue:
    """Decrypt data using Fernet."""

    if isinstance(ciphertext, DecryptedValue):
        return ciphertext

    if isinstance(ciphertext, str):
        try:
            ciphertext_bytes = ciphertext.encode("utf-8")
        except UnicodeDecodeError:
            ciphertext_bytes = str(ciphertext)
    else:
        ciphertext_bytes = ciphertext

    decrypted_bytes = FERNET_CLIENT.decrypt(ciphertext_bytes)
    decrypted_value = decrypted_bytes.decode("utf-8")

    return DecryptedValue(decrypted_value)
