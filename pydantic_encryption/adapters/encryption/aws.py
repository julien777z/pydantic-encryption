from functools import cache
from typing import Final

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")
require_optional_dependency("aws_encryption_sdk", "aws")

import aws_encryption_sdk
import botocore.session
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.key_providers.kms import StrictAwsKmsMasterKeyProvider
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.adapters.encryption.kms_metrics import MeteredMaterialsCache
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue

#: How long one data key may serve before the next encrypt fetches a fresh one.
DATA_KEY_MAX_AGE_SECONDS: Final[float] = 300.0
DATA_KEY_MAX_USES: Final[int] = 1000
DATA_KEY_MAX_BYTES: Final[int] = 2**30
MATERIALS_CACHE_SIZE: Final[int] = 512


def ciphertext_bytes(ciphertext: bytes | str | EncryptedValue) -> bytes:
    """Coerce decrypt() inputs to raw bytes preserving every original byte value 1:1."""

    if isinstance(ciphertext, str):
        return ciphertext.encode("latin-1")

    return bytes(ciphertext)


def kms_key_ids() -> list[str]:
    """Return the KMS key ARNs this process encrypts with and decrypts against."""

    if settings.AWS_KMS_KEY_ARN:
        return [settings.AWS_KMS_KEY_ARN]

    key_ids = [settings.AWS_KMS_ENCRYPT_KEY_ARN, settings.AWS_KMS_DECRYPT_KEY_ARN]
    resolved = [key_id for key_id in key_ids if key_id]

    if not resolved:
        raise ValueError(
            "AWS KMS requires at least one key ARN "
            "(AWS_KMS_KEY_ARN, AWS_KMS_ENCRYPT_KEY_ARN, or AWS_KMS_DECRYPT_KEY_ARN)."
        )

    return resolved


def botocore_session() -> botocore.session.Session:
    """Return a botocore session carrying the configured KMS region and credentials."""

    if not (
        settings.AWS_KMS_REGION and settings.AWS_KMS_ACCESS_KEY_ID and settings.AWS_KMS_SECRET_ACCESS_KEY
    ):
        raise ValueError(
            "AWS KMS requires AWS_KMS_REGION, AWS_KMS_ACCESS_KEY_ID, "
            "and AWS_KMS_SECRET_ACCESS_KEY to be set."
        )

    session = botocore.session.Session()
    session.set_credentials(settings.AWS_KMS_ACCESS_KEY_ID, settings.AWS_KMS_SECRET_ACCESS_KEY)
    session.set_config_variable("region", settings.AWS_KMS_REGION)

    return session


@cache
def crypto_materials() -> CachingCryptoMaterialsManager:
    """Return the process-wide materials manager that reuses one data key within its bounds."""

    # The Encryption SDK builds these constructors with attrs, so pyright cannot see their
    # generated signatures.
    provider = StrictAwsKmsMasterKeyProvider(  # pyright: ignore[reportCallIssue]
        key_ids=kms_key_ids(),
        botocore_session=botocore_session(),
    )

    return CachingCryptoMaterialsManager(
        cache=MeteredMaterialsCache(capacity=MATERIALS_CACHE_SIZE),  # pyright: ignore[reportCallIssue]
        max_age=DATA_KEY_MAX_AGE_SECONDS,  # pyright: ignore[reportCallIssue]
        max_messages_encrypted=DATA_KEY_MAX_USES,  # pyright: ignore[reportCallIssue]
        max_bytes_encrypted=DATA_KEY_MAX_BYTES,  # pyright: ignore[reportCallIssue]
        master_key_provider=provider,  # pyright: ignore[reportCallIssue]
    )


@cache
def crypto_client() -> aws_encryption_sdk.EncryptionSDKClient:
    """Return the process-wide Encryption SDK client."""

    return aws_encryption_sdk.EncryptionSDKClient(
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    )


class AWSAdapter(EncryptionAdapter):
    """Envelope encryption through the AWS Encryption SDK over a KMS-backed data key cache."""

    @classmethod
    def reset_cache(cls) -> None:
        """Drop the cached client and materials so the next call rebuilds them from current settings."""

        crypto_materials.cache_clear()
        crypto_client.cache_clear()

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        """Encrypt one value, reaching KMS only when the cached data key is spent."""

        if isinstance(plaintext, EncryptedValue):
            return plaintext

        ciphertext, _header = crypto_client().encrypt(
            source=encode_text(plaintext),
            materials_manager=crypto_materials(),
        )

        return EncryptedValue(ciphertext)

    @classmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        """Decrypt one value, reaching KMS only for a data key this process has not cached."""

        plaintext, _header = crypto_client().decrypt(
            source=ciphertext_bytes(ciphertext),
            materials_manager=crypto_materials(),
        )

        return plaintext.decode("utf-8")
