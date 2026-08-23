import threading
from typing import ClassVar

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")
require_optional_dependency("aws_encryption_sdk", "aws")

import aws_encryption_sdk
import botocore.session
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.caches.local import LocalCryptoMaterialsCache
from aws_encryption_sdk.key_providers.kms import StrictAwsKmsMasterKeyProvider
from aws_encryption_sdk.materials_managers.caching import CachingCryptoMaterialsManager

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue


def to_bytes(ciphertext: bytes | str | EncryptedValue) -> bytes:
    """Coerce decrypt() inputs to raw bytes preserving every original byte value 1:1."""

    if isinstance(ciphertext, str):
        return ciphertext.encode("latin-1")

    return bytes(ciphertext)


class AWSAdapter(EncryptionAdapter):
    """Envelope encryption through the AWS Encryption SDK over a KMS-backed data key cache."""

    materials_manager: ClassVar[CachingCryptoMaterialsManager | None] = None
    client: ClassVar[aws_encryption_sdk.EncryptionSDKClient | None] = None
    build_lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def kms_key_ids(cls) -> list[str]:
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

    @classmethod
    def botocore_session(cls) -> botocore.session.Session:
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

    @classmethod
    def crypto_materials(cls) -> CachingCryptoMaterialsManager:
        """Return the process-wide materials manager that reuses one data key within its bounds."""

        if cls.materials_manager is not None:
            return cls.materials_manager

        with cls.build_lock:
            if cls.materials_manager is None:
                # The Encryption SDK builds these constructors with attrs, so pyright cannot see
                # their generated signatures.
                cache = LocalCryptoMaterialsCache(
                    capacity=settings.KMS_MATERIALS_CACHE_SIZE  # pyright: ignore[reportCallIssue]
                )
                provider = StrictAwsKmsMasterKeyProvider(  # pyright: ignore[reportCallIssue]
                    key_ids=cls.kms_key_ids(),
                    botocore_session=cls.botocore_session(),
                )

                cls.materials_manager = CachingCryptoMaterialsManager(
                    cache=cache,  # pyright: ignore[reportCallIssue]
                    max_age=float(settings.KMS_DATA_KEY_MAX_AGE_SECONDS),  # pyright: ignore[reportCallIssue]
                    max_messages_encrypted=settings.KMS_DATA_KEY_MAX_USES,  # pyright: ignore[reportCallIssue]
                    max_bytes_encrypted=settings.KMS_DATA_KEY_MAX_BYTES,  # pyright: ignore[reportCallIssue]
                    master_key_provider=provider,  # pyright: ignore[reportCallIssue]
                )

            return cls.materials_manager

    @classmethod
    def crypto_client(cls) -> aws_encryption_sdk.EncryptionSDKClient:
        """Return the process-wide Encryption SDK client."""

        if cls.client is None:
            cls.client = aws_encryption_sdk.EncryptionSDKClient(
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
            )

        return cls.client

    @classmethod
    def reset_cache(cls) -> None:
        """Drop the cached materials manager so the next call rebuilds it from current settings."""

        with cls.build_lock:
            cls.materials_manager = None
            cls.client = None

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        """Encrypt one value, reaching KMS only when the cached data key is spent."""

        if isinstance(plaintext, EncryptedValue):
            return plaintext

        ciphertext, _header = cls.crypto_client().encrypt(
            source=encode_text(plaintext),
            materials_manager=cls.crypto_materials(),
        )

        return EncryptedValue(ciphertext)

    @classmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        """Decrypt one value, reaching KMS only for a data key this process has not cached."""

        plaintext, _header = cls.crypto_client().decrypt(
            source=to_bytes(ciphertext),
            materials_manager=cls.crypto_materials(),
        )

        return plaintext.decode("utf-8")
