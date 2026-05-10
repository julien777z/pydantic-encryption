import secrets
import struct
import threading
import time
from collections import OrderedDict
from typing import Any, ClassVar, Final

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue


CIPHERTEXT_MAGIC: Final[int] = 0xC0
CIPHERTEXT_VERSION: Final[int] = 0x01
HEADER_PACK_FORMAT: Final[str] = ">BBH"
HEADER_LENGTH: Final[int] = struct.calcsize(HEADER_PACK_FORMAT)
NONCE_LENGTH: Final[int] = 12
DATA_KEY_SPEC: Final[str] = "AES_256"


class _DataKeyCache:
    """Reuses a KMS data key for many encrypts and caches unwrapped keys for many decrypts.

    Encrypt path: holds one active plaintext+wrapped data key. Reuses it until either
    ``max_uses`` calls or ``max_age_seconds`` elapse, then triggers a fresh
    ``GenerateDataKey``. Random 96-bit nonces keep AES-GCM safe across the reuse
    window (NIST SP 800-38D allows ~2^32 messages per key under random nonces).

    Decrypt path: bounded LRU keyed by the wrapped data key bytes. A cache hit
    skips ``KMS.Decrypt``, which is the dominant per-cell cost on bulk reads.
    Capacity 0 disables the decrypt cache.
    """

    def __init__(
        self,
        *,
        max_uses: int,
        max_age_seconds: int,
        decrypt_cache_capacity: int,
    ) -> None:
        self._lock = threading.Lock()
        self._encrypt_key: tuple[bytes, bytes] | None = None
        self._encrypt_uses: int = 0
        self._encrypt_expires_at: float = 0.0
        self._max_uses = max_uses
        self._max_age_seconds = max_age_seconds
        self._decrypt_cache: OrderedDict[bytes, bytes] = OrderedDict()
        self._decrypt_cache_capacity = decrypt_cache_capacity

    def get_or_generate_encrypt_key(
        self, kms_client: Any, key_arn: str
    ) -> tuple[bytes, bytes]:
        """Return ``(plaintext_key, wrapped_key)``, reusing the active key when valid."""

        with self._lock:
            now = time.monotonic()
            active = self._encrypt_key
            if (
                active is not None
                and self._encrypt_uses < self._max_uses
                and now < self._encrypt_expires_at
            ):
                self._encrypt_uses += 1
                return active

        response = kms_client.generate_data_key(KeyId=key_arn, KeySpec=DATA_KEY_SPEC)
        plaintext_key = response["Plaintext"]
        wrapped_key = response["CiphertextBlob"]

        with self._lock:
            self._encrypt_key = (plaintext_key, wrapped_key)
            self._encrypt_uses = 1
            self._encrypt_expires_at = time.monotonic() + self._max_age_seconds

            return self._encrypt_key

    def get_decrypt_plaintext_key(self, wrapped_key: bytes) -> bytes | None:
        """Return the cached plaintext data key for ``wrapped_key`` or ``None`` on miss."""

        if self._decrypt_cache_capacity == 0:
            return None

        with self._lock:
            cached = self._decrypt_cache.get(wrapped_key)
            if cached is None:
                return None
            self._decrypt_cache.move_to_end(wrapped_key)

            return cached

    def store_decrypt_plaintext_key(self, wrapped_key: bytes, plaintext_key: bytes) -> None:
        """Insert a freshly unwrapped plaintext data key into the LRU."""

        if self._decrypt_cache_capacity == 0:
            return

        with self._lock:
            self._decrypt_cache[wrapped_key] = plaintext_key
            self._decrypt_cache.move_to_end(wrapped_key)
            while len(self._decrypt_cache) > self._decrypt_cache_capacity:
                self._decrypt_cache.popitem(last=False)

    def reset(self) -> None:
        """Drop all cached state. Used by tests to start from a clean slate."""

        with self._lock:
            self._encrypt_key = None
            self._encrypt_uses = 0
            self._encrypt_expires_at = 0.0
            self._decrypt_cache.clear()


class AWSAdapter(EncryptionAdapter):
    """AWS KMS adapter using GenerateDataKey + AES-256-GCM envelope encryption.

    Amortizes KMS calls with a per-process data-key cache: one ``GenerateDataKey``
    serves up to ``AWS_KMS_DATA_KEY_REUSE_MAX_USES`` encryptions or until
    ``AWS_KMS_DATA_KEY_REUSE_MAX_AGE_SECONDS`` elapse, and a bounded LRU caches
    unwrapped data keys so subsequent decrypts of cells that share a wrapped key
    skip ``KMS.Decrypt``.
    """

    _kms_client: ClassVar[Any | None] = None
    _data_key_cache: ClassVar[_DataKeyCache | None] = None

    @classmethod
    def _get_encrypt_key_arn(cls) -> str | None:
        """Get the ARN to use for encryption."""

        return settings.AWS_KMS_ENCRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN

    @classmethod
    def _get_decrypt_key_arn(cls) -> str | None:
        """Get the ARN to use for decryption (passed for cross-account scoping)."""

        return settings.AWS_KMS_DECRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN

    @classmethod
    def _get_kms_client(cls) -> Any:
        """Return the lazily-built boto3 KMS client, validating env on first use."""

        if cls._kms_client is not None:
            return cls._kms_client

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

        return cls._kms_client

    @classmethod
    def _get_data_key_cache(cls) -> _DataKeyCache:
        """Return the lazily-built data-key cache configured from settings."""

        if cls._data_key_cache is None:
            cls._data_key_cache = _DataKeyCache(
                max_uses=settings.AWS_KMS_DATA_KEY_REUSE_MAX_USES,
                max_age_seconds=settings.AWS_KMS_DATA_KEY_REUSE_MAX_AGE_SECONDS,
                decrypt_cache_capacity=settings.AWS_KMS_DATA_KEY_DECRYPT_CACHE_CAPACITY,
            )

        return cls._data_key_cache

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        encrypt_arn = cls._get_encrypt_key_arn()
        if not encrypt_arn:
            raise ValueError(
                "No encryption key configured. Set AWS_KMS_KEY_ARN or AWS_KMS_ENCRYPT_KEY_ARN."
            )

        plaintext_data_key, wrapped_data_key = cls._get_data_key_cache().get_or_generate_encrypt_key(
            cls._get_kms_client(), encrypt_arn,
        )

        nonce = secrets.token_bytes(NONCE_LENGTH)
        sealed = AESGCM(plaintext_data_key).encrypt(nonce, plaintext, None)

        return EncryptedValue(
            struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, len(wrapped_data_key))
            + wrapped_data_key
            + nonce
            + sealed
        )

    @classmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        if isinstance(ciphertext, str):
            blob = ciphertext.encode("utf-8")
        else:
            blob = bytes(ciphertext)

        if len(blob) < HEADER_LENGTH:
            raise ValueError("Ciphertext is too short to be a valid AWS KMS envelope.")

        magic, version, wrapped_key_length = struct.unpack(HEADER_PACK_FORMAT, blob[:HEADER_LENGTH])
        if magic != CIPHERTEXT_MAGIC:
            raise ValueError(
                "Unrecognized ciphertext format for AWS KMS adapter "
                f"(expected magic {CIPHERTEXT_MAGIC:#x}, got {magic:#x})."
            )
        if version != CIPHERTEXT_VERSION:
            raise ValueError(f"Unsupported AWS KMS ciphertext version: {version}")

        offset = HEADER_LENGTH
        wrapped_data_key = blob[offset:offset + wrapped_key_length]
        offset += wrapped_key_length

        nonce = blob[offset:offset + NONCE_LENGTH]
        sealed = blob[offset + NONCE_LENGTH:]

        cache = cls._get_data_key_cache()
        plaintext_data_key = cache.get_decrypt_plaintext_key(wrapped_data_key)
        if plaintext_data_key is None:
            decrypt_kwargs: dict[str, Any] = {"CiphertextBlob": wrapped_data_key}
            decrypt_arn = cls._get_decrypt_key_arn()
            if decrypt_arn:
                decrypt_kwargs["KeyId"] = decrypt_arn
            plaintext_data_key = cls._get_kms_client().decrypt(**decrypt_kwargs)["Plaintext"]
            cache.store_decrypt_plaintext_key(wrapped_data_key, plaintext_data_key)

        plaintext = AESGCM(plaintext_data_key).decrypt(nonce, sealed, None)

        return plaintext.decode("utf-8")
