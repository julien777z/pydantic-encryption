import asyncio
import secrets
import struct
from typing import Any, ClassVar, Final

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")
require_optional_dependency("aioboto3", "aws")

import aioboto3
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


def _to_bytes(ciphertext: bytes | str | EncryptedValue) -> bytes:
    """Coerce decrypt() inputs to raw bytes preserving every original byte value 1:1."""

    if isinstance(ciphertext, str):
        return ciphertext.encode("latin-1")

    return bytes(ciphertext)


def _kms_kwargs() -> dict[str, str]:
    """Return boto3/aioboto3 kwargs for the configured KMS region + credentials."""

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

    return {
        "region_name": settings.AWS_KMS_REGION,
        "aws_access_key_id": settings.AWS_KMS_ACCESS_KEY_ID,
        "aws_secret_access_key": settings.AWS_KMS_SECRET_ACCESS_KEY,
    }


def _seal(plaintext_data_key: bytes, wrapped_data_key: bytes, plaintext: bytes) -> EncryptedValue:
    """Wrap plaintext under a fresh AES-GCM nonce and pack ``[magic][ver][wrapped][nonce][sealed]``."""

    nonce = secrets.token_bytes(NONCE_LENGTH)
    sealed = AESGCM(plaintext_data_key).encrypt(nonce, plaintext, None)

    return EncryptedValue(
        struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, len(wrapped_data_key))
        + wrapped_data_key
        + nonce
        + sealed
    )


def _open(blob: bytes) -> tuple[bytes, bytes, bytes]:
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
    """AWS KMS adapter using GenerateDataKey + AES-256-GCM envelope encryption."""

    _sync_client: ClassVar[Any | None] = None
    _async_client: ClassVar[Any | None] = None
    _async_client_ctx: ClassVar[Any | None] = None
    _async_loop: ClassVar[asyncio.AbstractEventLoop | None] = None
    _async_init_lock: ClassVar[asyncio.Lock | None] = None

    @classmethod
    def _encrypt_arn(cls) -> str:
        """Return the encryption ARN, rejecting decrypt-only (read-only) configurations."""

        arn = settings.AWS_KMS_ENCRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN
        if not arn:
            raise ValueError(
                "encrypt() requires AWS_KMS_KEY_ARN or AWS_KMS_ENCRYPT_KEY_ARN; "
                "AWS_KMS_DECRYPT_KEY_ARN alone is decrypt-only."
            )

        return arn

    @classmethod
    def _decrypt_kwargs(cls, wrapped_data_key: bytes) -> dict[str, Any]:
        """Build ``KMS.Decrypt`` kwargs, scoping by KeyId when one is configured."""

        kwargs: dict[str, Any] = {"CiphertextBlob": wrapped_data_key}
        decrypt_arn = settings.AWS_KMS_DECRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN
        if decrypt_arn:
            kwargs["KeyId"] = decrypt_arn

        return kwargs

    @classmethod
    def _sync_kms(cls) -> Any:
        """Return the lazily-built sync boto3 KMS client used by sync code paths."""

        if cls._sync_client is None:
            cls._sync_client = boto3.client("kms", **_kms_kwargs())

        return cls._sync_client

    @classmethod
    async def _async_kms(cls) -> Any:
        """Return the lazily-built aioboto3 KMS client, opened once per event loop."""

        loop = asyncio.get_running_loop()
        if cls._async_client is not None and cls._async_loop is loop:
            return cls._async_client

        if cls._async_init_lock is None:
            cls._async_init_lock = asyncio.Lock()

        async with cls._async_init_lock:
            if cls._async_client is not None and cls._async_loop is loop:
                return cls._async_client

            ctx = aioboto3.Session(**_kms_kwargs()).client("kms")
            cls._async_client = await ctx.__aenter__()
            cls._async_client_ctx = ctx
            cls._async_loop = loop

            return cls._async_client

    @classmethod
    async def aclose_async_kms(cls) -> None:
        """Close the active aioboto3 KMS client (must be called from the loop that opened it)."""

        ctx = cls._async_client_ctx
        if ctx is None:
            return

        cls._async_client = None
        cls._async_client_ctx = None
        cls._async_loop = None
        await ctx.__aexit__(None, None, None)

    @classmethod
    def encrypt(cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        response = cls._sync_kms().generate_data_key(KeyId=cls._encrypt_arn(), KeySpec=DATA_KEY_SPEC)

        return _seal(response["Plaintext"], response["CiphertextBlob"], plaintext)

    @classmethod
    async def async_encrypt(
        cls, plaintext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> EncryptedValue:
        if isinstance(plaintext, EncryptedValue):
            return plaintext
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        kms = await cls._async_kms()
        response = await kms.generate_data_key(KeyId=cls._encrypt_arn(), KeySpec=DATA_KEY_SPEC)

        return _seal(response["Plaintext"], response["CiphertextBlob"], plaintext)

    @classmethod
    def decrypt(cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None) -> str:
        wrapped, nonce, sealed = _open(_to_bytes(ciphertext))

        plaintext_data_key = cls._sync_kms().decrypt(**cls._decrypt_kwargs(wrapped))["Plaintext"]

        return AESGCM(plaintext_data_key).decrypt(nonce, sealed, None).decode("utf-8")

    @classmethod
    async def async_decrypt(
        cls, ciphertext: bytes | str | EncryptedValue, *, key: str | None = None
    ) -> str:
        wrapped, nonce, sealed = _open(_to_bytes(ciphertext))

        kms = await cls._async_kms()
        response = await kms.decrypt(**cls._decrypt_kwargs(wrapped))

        return AESGCM(response["Plaintext"]).decrypt(nonce, sealed, None).decode("utf-8")
