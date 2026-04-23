import threading
from typing import Any, ClassVar

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")
require_optional_dependency("aws_encryption_sdk", "aws")
require_optional_dependency("cachetools", "aws")

import aws_encryption_sdk
import boto3
from aws_cryptographic_material_providers.mpl import AwsCryptographicMaterialProviders
from aws_cryptographic_material_providers.mpl.config import MaterialProvidersConfig
from aws_cryptographic_material_providers.mpl.models import CreateAwsKmsKeyringInput
from aws_encryption_sdk import CommitmentPolicy
from cachetools import LRUCache

from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue


class AWSAdapter(EncryptionAdapter):
    """AWS KMS adapter with an in-process ciphertext->plaintext cache on decrypt."""

    _kms_client: ClassVar[Any | None] = None
    _encryption_client: ClassVar[Any | None] = None
    _mat_prov: ClassVar[Any | None] = None
    _encrypt_keyring: ClassVar[Any | None] = None
    _decrypt_keyring: ClassVar[Any | None] = None
    _plaintext_cache: ClassVar[LRUCache[bytes, str] | None] = None
    _plaintext_cache_lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def _get_encrypt_key_arn(cls) -> str | None:
        """Get the ARN to use for encryption."""

        return settings.AWS_KMS_ENCRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN

    @classmethod
    def _get_decrypt_key_arn(cls) -> str | None:
        """Get the ARN to use for decryption."""

        return settings.AWS_KMS_DECRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN

    @classmethod
    def _init_base_clients(cls) -> None:
        """Initialize base AWS clients (KMS, encryption SDK, material providers)."""

        if cls._kms_client is None:
            has_key = (
                settings.AWS_KMS_KEY_ARN
                or settings.AWS_KMS_ENCRYPT_KEY_ARN
                or settings.AWS_KMS_DECRYPT_KEY_ARN
            )
            if not (
                has_key
                and settings.AWS_KMS_REGION
                and settings.AWS_KMS_ACCESS_KEY_ID
                and settings.AWS_KMS_SECRET_ACCESS_KEY
            ):
                raise ValueError(
                    "AWS KMS requires AWS_KMS_REGION, AWS_KMS_ACCESS_KEY_ID, "
                    "AWS_KMS_SECRET_ACCESS_KEY, and at least one key ARN "
                    "(AWS_KMS_KEY_ARN, AWS_KMS_ENCRYPT_KEY_ARN, or AWS_KMS_DECRYPT_KEY_ARN) to be set."
                )

            cls._kms_client = boto3.client(
                "kms",
                region_name=settings.AWS_KMS_REGION,
                aws_access_key_id=settings.AWS_KMS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_KMS_SECRET_ACCESS_KEY,
            )

        if cls._encryption_client is None:
            cls._encryption_client = aws_encryption_sdk.EncryptionSDKClient(
                commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
            )

        if cls._mat_prov is None:
            cls._mat_prov = AwsCryptographicMaterialProviders(config=MaterialProvidersConfig())

    @classmethod
    def _get_encrypt_keyring(cls) -> Any:
        """Get or create the keyring for encryption."""

        cls._init_base_clients()

        if cls._encrypt_keyring is None:
            encrypt_arn = cls._get_encrypt_key_arn()

            if not encrypt_arn:
                raise ValueError(
                    "No encryption key configured. Set AWS_KMS_KEY_ARN or AWS_KMS_ENCRYPT_KEY_ARN."
                )
            keyring_input = CreateAwsKmsKeyringInput(
                kms_key_id=encrypt_arn,
                kms_client=cls._kms_client,
            )
            cls._encrypt_keyring = cls._mat_prov.create_aws_kms_keyring(input=keyring_input)

        return cls._encrypt_keyring

    @classmethod
    def _get_decrypt_keyring(cls) -> Any:
        """Get or create the keyring for decryption."""

        cls._init_base_clients()

        if cls._decrypt_keyring is None:
            decrypt_arn = cls._get_decrypt_key_arn()

            if not decrypt_arn:
                raise ValueError(
                    "No decryption key configured. Set AWS_KMS_KEY_ARN or AWS_KMS_DECRYPT_KEY_ARN."
                )
            keyring_input = CreateAwsKmsKeyringInput(
                kms_key_id=decrypt_arn,
                kms_client=cls._kms_client,
            )

            cls._decrypt_keyring = cls._mat_prov.create_aws_kms_keyring(input=keyring_input)

        return cls._decrypt_keyring

    @classmethod
    def _cache_lookup(cls, ciphertext: bytes) -> str | None:
        """Return the cached plaintext for a ciphertext, or None on miss."""

        if not settings.AWS_KMS_PLAINTEXT_CACHE_ENABLED:
            return None

        with cls._plaintext_cache_lock:
            if cls._plaintext_cache is None:
                return None
            return cls._plaintext_cache.get(ciphertext)

    @classmethod
    def _cache_store(cls, ciphertext: bytes, plaintext: str) -> None:
        """Insert a ciphertext->plaintext mapping; LRU eviction is handled by the cache."""

        if not settings.AWS_KMS_PLAINTEXT_CACHE_ENABLED:
            return

        capacity = settings.AWS_KMS_PLAINTEXT_CACHE_CAPACITY
        if capacity <= 0:
            return

        with cls._plaintext_cache_lock:
            if cls._plaintext_cache is None:
                cls._plaintext_cache = LRUCache(maxsize=capacity)
            cls._plaintext_cache[ciphertext] = plaintext

    @classmethod
    def _clear_plaintext_cache(cls) -> None:
        """Reset the plaintext cache (test hook; not used by application code)."""

        with cls._plaintext_cache_lock:
            cls._plaintext_cache = None

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        cls._init_base_clients()
        keyring = cls._get_encrypt_keyring()

        ciphertext, _ = cls._encryption_client.encrypt(
            source=plaintext,
            keyring=keyring,
        )

        return EncryptedValue(ciphertext)

    @classmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        if isinstance(ciphertext, str):
            ciphertext_bytes = ciphertext.encode("utf-8")
        else:
            ciphertext_bytes = bytes(ciphertext)

        cached = cls._cache_lookup(ciphertext_bytes)
        if cached is not None:
            return cached

        cls._init_base_clients()
        keyring = cls._get_decrypt_keyring()

        plaintext, _ = cls._encryption_client.decrypt(
            source=ciphertext_bytes,
            keyring=keyring,
        )

        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8")

        cls._cache_store(ciphertext_bytes, plaintext)
        return plaintext
