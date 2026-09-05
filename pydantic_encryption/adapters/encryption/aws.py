import asyncio
import secrets
import struct
import threading
import time
from collections import OrderedDict
from typing import Any, ClassVar, Final

from pydantic import BaseModel, Field

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")

import boto3
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue

CIPHERTEXT_MAGIC: Final[int] = 0xC0
CIPHERTEXT_VERSION: Final[int] = 0x01
HEADER_PACK_FORMAT: Final[str] = ">BBH"
HEADER_LENGTH: Final[int] = struct.calcsize(HEADER_PACK_FORMAT)
NONCE_LENGTH: Final[int] = 12
DATA_KEY_SPEC: Final[str] = "AES_256"


class DataKey(BaseModel):
    """A KMS data key held in memory, with how far its reuse has gone."""

    plaintext: bytes = Field(repr=False)
    wrapped: bytes = Field(repr=False)
    issued_at: float
    uses: int = 0

    def is_spent(self, max_uses: int, max_age_seconds: float, now: float) -> bool:
        """Return whether this key has exhausted either of its reuse bounds."""

        return self.uses >= max_uses or now - self.issued_at >= max_age_seconds


class UnwrappedDataKey(BaseModel):
    """A data key KMS has unwrapped for this process, kept until it expires."""

    plaintext: bytes = Field(repr=False)
    unwrapped_at: float

    def has_expired(self, max_age_seconds: float, now: float) -> bool:
        """Return whether this unwrapped key has outlived its retention."""

        return now - self.unwrapped_at >= max_age_seconds


def to_bytes(ciphertext: bytes | str | EncryptedValue) -> bytes:
    """Coerce decrypt() inputs to raw bytes preserving every original byte value 1:1."""

    if isinstance(ciphertext, str):
        return ciphertext.encode("latin-1")

    return bytes(ciphertext)


def kms_kwargs() -> dict[str, str]:
    """Return boto3 kwargs for the configured KMS region and credentials."""

    has_key = settings.AWS_KMS_KEY_ARN or settings.AWS_KMS_ENCRYPT_KEY_ARN or settings.AWS_KMS_DECRYPT_KEY_ARN
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

    return {
        "region_name": settings.AWS_KMS_REGION,
        "aws_access_key_id": settings.AWS_KMS_ACCESS_KEY_ID,
        "aws_secret_access_key": settings.AWS_KMS_SECRET_ACCESS_KEY,
    }


def kms_transport_config() -> Config:
    """Build the bounded KMS transport configuration."""

    return Config(
        connect_timeout=settings.AWS_KMS_CONNECT_TIMEOUT_SECONDS,
        read_timeout=settings.AWS_KMS_READ_TIMEOUT_SECONDS,
        retries={"mode": "standard", "total_max_attempts": settings.AWS_KMS_MAX_ATTEMPTS},
    )


def seal(
    plaintext_data_key: bytes,
    wrapped_data_key: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> EncryptedValue:
    """Wrap plaintext under a fresh AES-GCM nonce and pack ``[magic][ver][wrapped][nonce][sealed]``."""

    nonce = secrets.token_bytes(NONCE_LENGTH)
    sealed = AESGCM(plaintext_data_key).encrypt(nonce, plaintext, associated_data)

    return EncryptedValue(
        struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, len(wrapped_data_key))
        + wrapped_data_key
        + nonce
        + sealed
    )


def unseal(plaintext_data_key: bytes, nonce: bytes, sealed: bytes, associated_data: bytes) -> str:
    """Open one AES-GCM sealed value with an already unwrapped data key."""

    return AESGCM(plaintext_data_key).decrypt(nonce, sealed, associated_data).decode("utf-8")


def open(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Validate the envelope header and split into ``(wrapped_data_key, nonce, sealed)``."""

    if len(blob) < HEADER_LENGTH:
        raise ValueError("Ciphertext is too short to be a valid AWS KMS envelope.")

    magic, version, wrapped_len = struct.unpack(HEADER_PACK_FORMAT, blob[:HEADER_LENGTH])
    if magic != CIPHERTEXT_MAGIC:
        raise ValueError(
            "Unrecognized ciphertext format for AWS KMS adapter "
            f"(expected magic {CIPHERTEXT_MAGIC:#x}, got {magic:#x})."
        )
    if version != CIPHERTEXT_VERSION:
        raise ValueError(f"Unsupported AWS KMS ciphertext version: {version}")

    end_wrapped = HEADER_LENGTH + wrapped_len
    end_nonce = end_wrapped + NONCE_LENGTH
    if len(blob) < end_nonce:
        raise ValueError("Ciphertext is truncated: missing wrapped data key or nonce.")

    return blob[HEADER_LENGTH:end_wrapped], blob[end_wrapped:end_nonce], blob[end_nonce:]


class AWSAdapter(EncryptionAdapter):
    """AWS KMS envelope encryption, reusing each data key across values within configured bounds."""

    _sync_client: ClassVar[Any | None] = None

    encrypt_key: ClassVar[DataKey | None] = None
    unwrapped_keys: ClassVar[OrderedDict[bytes, UnwrappedDataKey]] = OrderedDict()
    cache_lock: ClassVar[threading.Lock] = threading.Lock()
    generation_lock: ClassVar[threading.Lock] = threading.Lock()
    unwrapping_lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def encrypt_arn(cls) -> str:
        """Return the encryption ARN, rejecting decrypt-only (read-only) configurations."""

        arn = settings.AWS_KMS_ENCRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN
        if not arn:
            raise ValueError(
                "encrypt() requires AWS_KMS_KEY_ARN or AWS_KMS_ENCRYPT_KEY_ARN; "
                "AWS_KMS_DECRYPT_KEY_ARN alone is decrypt-only."
            )

        return arn

    @classmethod
    def decrypt_kwargs(cls, wrapped_data_key: bytes) -> dict[str, Any]:
        """Build ``KMS.Decrypt`` kwargs, scoping by KeyId when one is configured."""

        kwargs: dict[str, Any] = {"CiphertextBlob": wrapped_data_key}
        decrypt_arn = settings.AWS_KMS_DECRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN
        if decrypt_arn:
            kwargs["KeyId"] = decrypt_arn

        return kwargs

    @classmethod
    def sync_kms(cls) -> Any:
        """Return the lazily-built sync boto3 KMS client used by sync code paths."""

        if cls._sync_client is None:
            cls._sync_client = boto3.client("kms", config=kms_transport_config(), **kms_kwargs())

        return cls._sync_client

    @classmethod
    def claim_encrypt_key(cls) -> DataKey | None:
        """Return the held data key and count this use, or ``None`` once it is spent."""

        with cls.cache_lock:
            held = cls.encrypt_key
            if held is None or held.is_spent(
                settings.AWS_KMS_DATA_KEY_MAX_USES,
                settings.AWS_KMS_DATA_KEY_MAX_AGE_SECONDS,
                time.monotonic(),
            ):
                return None

            held.uses += 1

            return held

    @classmethod
    def hold_encrypt_key(cls, response: dict[str, Any]) -> DataKey:
        """Hold a freshly generated data key for reuse, counting its first use."""

        held = DataKey(
            plaintext=response["Plaintext"],
            wrapped=response["CiphertextBlob"],
            issued_at=time.monotonic(),
            uses=1,
        )

        with cls.cache_lock:
            cls.encrypt_key = held

        return held

    @classmethod
    def remember_unwrapped_key(cls, wrapped: bytes, plaintext: bytes) -> None:
        """Keep an unwrapped data key, evicting the least recently used once the cache is full."""

        with cls.cache_lock:
            cls.unwrapped_keys[wrapped] = UnwrappedDataKey(plaintext=plaintext, unwrapped_at=time.monotonic())
            cls.unwrapped_keys.move_to_end(wrapped)

            while len(cls.unwrapped_keys) > settings.AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE:
                cls.unwrapped_keys.popitem(last=False)

    @classmethod
    def recall_unwrapped_key(cls, wrapped: bytes) -> bytes | None:
        """Return a still-fresh unwrapped data key, marking it most recently used."""

        with cls.cache_lock:
            unwrapped = cls.unwrapped_keys.get(wrapped)
            if unwrapped is None:
                return None

            if unwrapped.has_expired(settings.AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS, time.monotonic()):
                del cls.unwrapped_keys[wrapped]

                return None

            cls.unwrapped_keys.move_to_end(wrapped)

            return unwrapped.plaintext

    @classmethod
    def reset_cache(cls) -> None:
        """Drop every held key so the next call goes back to KMS."""

        with cls.cache_lock:
            cls.encrypt_key = None
            cls.unwrapped_keys.clear()

    @classmethod
    def generated_encrypt_key(cls) -> DataKey:
        """Return the data key to seal with, generating one through KMS only once it is spent."""

        with cls.generation_lock:
            return cls.claim_encrypt_key() or cls.hold_encrypt_key(
                cls.sync_kms().generate_data_key(KeyId=cls.encrypt_arn(), KeySpec=DATA_KEY_SPEC)
            )

    @classmethod
    def unwrapped_key(cls, wrapped: bytes) -> bytes:
        """Return the plaintext of a wrapped data key, unwrapping it through KMS once per process."""

        plaintext = cls.recall_unwrapped_key(wrapped)
        if plaintext is not None:
            return plaintext

        with cls.unwrapping_lock:
            plaintext = cls.recall_unwrapped_key(wrapped)
            if plaintext is None:
                plaintext = cls.sync_kms().decrypt(**cls.decrypt_kwargs(wrapped))["Plaintext"]
                cls.remember_unwrapped_key(wrapped, plaintext)

        return plaintext

    @classmethod
    async def async_unwrapped_key(cls, wrapped: bytes) -> bytes:
        """Return the plaintext of a wrapped data key, leaving the loop only for a cold KMS unwrap."""

        plaintext = cls.recall_unwrapped_key(wrapped)
        if plaintext is not None:
            return plaintext

        return await asyncio.to_thread(cls.unwrapped_key, wrapped)

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        held = cls.claim_encrypt_key() or cls.generated_encrypt_key()

        return seal(held.plaintext, held.wrapped, encode_text(plaintext), associated_data)

    @classmethod
    async def async_encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext

        held = cls.claim_encrypt_key() or await asyncio.to_thread(cls.generated_encrypt_key)

        return seal(held.plaintext, held.wrapped, encode_text(plaintext), associated_data)

    @classmethod
    def decrypt(
        cls,
        ciphertext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> str:
        wrapped, nonce, sealed = open(to_bytes(ciphertext))

        return unseal(cls.unwrapped_key(wrapped), nonce, sealed, associated_data)

    @classmethod
    async def async_decrypt(
        cls,
        ciphertext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> str:
        wrapped, nonce, sealed = open(to_bytes(ciphertext))

        return unseal(await cls.async_unwrapped_key(wrapped), nonce, sealed, associated_data)
