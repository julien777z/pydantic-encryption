import asyncio
import os
import secrets
import struct
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from typing import ClassVar, Final

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("boto3", "aws")

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.config import settings
from pydantic_encryption.models.kms import (
    DataKey,
    DataKeyDecryptRequest,
    DataKeyGenerateRequest,
    DecryptedDataKey,
    GeneratedDataKey,
    HeldDataKey,
    KMSClientOptions,
)
from pydantic_encryption.types import EncryptedValue

CIPHERTEXT_MAGIC: Final[int] = 0xC0
CIPHERTEXT_VERSION: Final[int] = 0x02
HEADER_PACK_FORMAT: Final[str] = ">BBH"
HEADER_LENGTH: Final[int] = struct.calcsize(HEADER_PACK_FORMAT)
NONCE_LENGTH: Final[int] = 12
DATA_KEY_SPEC: Final[str] = "AES_256"


def to_bytes(ciphertext: bytes | str | EncryptedValue) -> bytes:
    """Coerce decrypt() inputs to raw bytes preserving every original byte value 1:1."""

    if isinstance(ciphertext, str):
        return ciphertext.encode("latin-1")

    return bytes(ciphertext)


def kms_client_options() -> KMSClientOptions:
    """Return the boto3 KMS client options: the configured region, credentials and transport bounds."""

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

    return KMSClientOptions(
        region_name=settings.AWS_KMS_REGION,
        aws_access_key_id=settings.AWS_KMS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_KMS_SECRET_ACCESS_KEY,
        config=Config(
            connect_timeout=settings.AWS_KMS_CONNECT_TIMEOUT_SECONDS,
            read_timeout=settings.AWS_KMS_READ_TIMEOUT_SECONDS,
            retries={"mode": "standard", "total_max_attempts": settings.AWS_KMS_MAX_ATTEMPTS},
        ),
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

    kms_client: ClassVar[BaseClient | None] = None
    client_lock: ClassVar[threading.Lock] = threading.Lock()

    encrypt_key: ClassVar[DataKey | None] = None
    unwrapped_keys: ClassVar[OrderedDict[bytes, HeldDataKey]] = OrderedDict()
    cache_lock: ClassVar[threading.Lock] = threading.Lock()
    expiry_timer: ClassVar[threading.Timer | None] = None
    expiry_due: ClassVar[float] = 0.0

    generation_lock: ClassVar[threading.Lock] = threading.Lock()
    generating: ClassVar[Future[None] | None] = None

    unwrapping_condition: ClassVar[threading.Condition] = threading.Condition()
    unwrapping: ClassVar[dict[bytes, Future[bytes]]] = {}

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
    def decrypt_kwargs(cls, wrapped_data_key: bytes) -> DataKeyDecryptRequest:
        """Build ``KMS.Decrypt`` kwargs, scoping by KeyId when one is configured."""

        kwargs = DataKeyDecryptRequest(CiphertextBlob=wrapped_data_key)
        decrypt_arn = settings.AWS_KMS_DECRYPT_KEY_ARN or settings.AWS_KMS_KEY_ARN
        if decrypt_arn:
            kwargs["KeyId"] = decrypt_arn

        return kwargs

    @classmethod
    def client(cls) -> BaseClient:
        """Return the lazily built boto3 KMS client."""

        if cls.kms_client is None:
            with cls.client_lock:
                if cls.kms_client is None:
                    cls.kms_client = boto3.client("kms", **kms_client_options())

        return cls.kms_client

    @classmethod
    def schedule_expiry(cls) -> None:
        """Arrange for the soonest-expiring held key to be dropped when it expires; needs ``cache_lock``."""

        expiries = [held.expires_at for held in cls.unwrapped_keys.values()]

        if cls.encrypt_key is not None:
            expiries.append(cls.encrypt_key.expires_at)

        if not expiries:
            return

        due = min(expiries)

        if cls.expiry_timer is not None:
            if cls.expiry_due <= due:
                return

            cls.expiry_timer.cancel()

        timer = threading.Timer(max(due - time.monotonic(), 0.0), cls.drop_expired_keys)
        timer.daemon = True

        cls.expiry_timer = timer
        cls.expiry_due = due

        timer.start()

    @classmethod
    def drop_expired_keys(cls) -> None:
        """Drop every held data key past its lifetime, then wait for the next one to expire."""

        with cls.cache_lock:
            now = time.monotonic()

            if cls.encrypt_key is not None and cls.encrypt_key.has_expired(now):
                cls.encrypt_key = None

            for wrapped in [wrapped for wrapped, held in cls.unwrapped_keys.items() if held.has_expired(now)]:
                del cls.unwrapped_keys[wrapped]

            if cls.expiry_timer is threading.current_thread():
                cls.expiry_timer = None

            cls.schedule_expiry()

    @classmethod
    def claim_encrypt_key(cls) -> DataKey | None:
        """Return the held data key and count this use, or ``None`` once it is spent, dropping a spent key."""

        with cls.cache_lock:
            held = cls.encrypt_key

            if held is None or held.has_expired(time.monotonic()):
                cls.encrypt_key = None

                return None

            held.uses_left -= 1

            if not held.uses_left:
                cls.encrypt_key = None

            return held

    @classmethod
    def hold_encrypt_key(cls, response: GeneratedDataKey) -> DataKey:
        """Hold a freshly generated data key for reuse, counting its first use."""

        held = DataKey(
            plaintext=response["Plaintext"],
            wrapped=response["CiphertextBlob"],
            expires_at=time.monotonic() + settings.AWS_KMS_DATA_KEY_MAX_AGE_SECONDS,
            uses_left=settings.AWS_KMS_DATA_KEY_MAX_USES - 1,
        )

        if held.uses_left:
            with cls.cache_lock:
                cls.encrypt_key = held
                cls.schedule_expiry()

        return held

    @classmethod
    def remember_unwrapped_key(cls, wrapped: bytes, plaintext: bytes) -> None:
        """Keep an unwrapped data key, evicting the least recently used once the cache is full."""

        held = HeldDataKey(
            plaintext=plaintext,
            expires_at=time.monotonic() + settings.AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS,
        )

        with cls.cache_lock:
            cls.unwrapped_keys[wrapped] = held
            cls.unwrapped_keys.move_to_end(wrapped)

            while len(cls.unwrapped_keys) > settings.AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE:
                cls.unwrapped_keys.popitem(last=False)

            cls.schedule_expiry()

    @classmethod
    def recall_unwrapped_key(cls, wrapped: bytes) -> bytes | None:
        """Return a still-fresh unwrapped data key, marking it most recently used."""

        with cls.cache_lock:
            held = cls.unwrapped_keys.get(wrapped)
            if held is None:
                return None

            if held.has_expired(time.monotonic()):
                del cls.unwrapped_keys[wrapped]

                return None

            cls.unwrapped_keys.move_to_end(wrapped)

            return held.plaintext

    @classmethod
    def release_generation(cls) -> None:
        """Mark that no data key generation is in flight, so the next caller starts one."""

        with cls.generation_lock:
            cls.generating = None

    @classmethod
    def generated_encrypt_key(cls, pending: Future[None]) -> DataKey:
        """Generate a data key through KMS, then settle the generation its waiting callers share."""

        try:
            held = cls.hold_encrypt_key(
                cls.client().generate_data_key(
                    **DataKeyGenerateRequest(KeyId=cls.encrypt_arn(), KeySpec=DATA_KEY_SPEC)
                )
            )
        except BaseException as exc:
            cls.release_generation()
            pending.set_exception(exc)

            raise

        cls.release_generation()
        pending.set_result(None)

        return held

    @classmethod
    def encrypt_key_for_use(cls) -> DataKey:
        """Return the data key to seal with, sharing one KMS generation and its outcome among callers."""

        while True:
            with cls.generation_lock:
                held = cls.claim_encrypt_key()

                if held is not None:
                    return held

                pending = cls.generating
                owns_generation = pending is None

                if pending is None:
                    pending = cls.generating = Future[None]()

            if owns_generation:
                return cls.generated_encrypt_key(pending)

            pending.result()

    @classmethod
    def unwrapped_key(cls, wrapped: bytes) -> bytes:
        """Share one bounded in-flight KMS unwrap per data key, keeping distinct keys concurrent."""

        with cls.unwrapping_condition:
            while True:
                plaintext = cls.recall_unwrapped_key(wrapped)

                if plaintext is not None:
                    return plaintext

                pending = cls.unwrapping.get(wrapped)

                if pending is not None:
                    owns_unwrap = False
                    break

                if len(cls.unwrapping) < settings.AWS_KMS_MAX_IN_FLIGHT_UNWRAPS:
                    pending = Future[bytes]()
                    cls.unwrapping[wrapped] = pending
                    owns_unwrap = True
                    break

                cls.unwrapping_condition.wait()

        if not owns_unwrap:
            return pending.result()

        try:
            response: DecryptedDataKey = cls.client().decrypt(**cls.decrypt_kwargs(wrapped))
            plaintext = response["Plaintext"]

            cls.remember_unwrapped_key(wrapped, plaintext)
            pending.set_result(plaintext)

            return plaintext
        except BaseException as exc:
            pending.set_exception(exc)

            raise
        finally:
            with cls.unwrapping_condition:
                del cls.unwrapping[wrapped]
                cls.unwrapping_condition.notify_all()

    @classmethod
    async def async_unwrapped_key(cls, wrapped: bytes) -> bytes:
        """Return the plaintext of a wrapped data key, leaving the loop only for a cold KMS unwrap."""

        plaintext = cls.recall_unwrapped_key(wrapped)
        if plaintext is not None:
            return plaintext

        return await asyncio.to_thread(cls.unwrapped_key, wrapped)

    @classmethod
    def reset_after_fork(cls) -> None:
        """Give a forked child fresh locks and none of the keys, client or calls its parent held."""

        cls.kms_client = None
        cls.client_lock = threading.Lock()

        cls.encrypt_key = None
        cls.unwrapped_keys = OrderedDict()
        cls.cache_lock = threading.Lock()
        cls.expiry_timer = None

        cls.generation_lock = threading.Lock()
        cls.generating = None

        cls.unwrapping_condition = threading.Condition()
        cls.unwrapping = {}

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        """Seal plaintext under the held data key, bound to its associated data."""

        if isinstance(plaintext, EncryptedValue):
            return plaintext

        held = cls.encrypt_key_for_use()

        return seal(held.plaintext, held.wrapped, encode_text(plaintext), associated_data)

    @classmethod
    async def async_encrypt(
        cls,
        plaintext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> EncryptedValue:
        """Seal plaintext, generating a data key off the event loop only when one is needed."""

        if isinstance(plaintext, EncryptedValue):
            return plaintext

        held = cls.claim_encrypt_key() or await asyncio.to_thread(cls.encrypt_key_for_use)

        return seal(held.plaintext, held.wrapped, encode_text(plaintext), associated_data)

    @classmethod
    def decrypt(
        cls,
        ciphertext: bytes | str | EncryptedValue,
        *,
        key: str | None = None,
        associated_data: bytes,
    ) -> str:
        """Open a sealed value, bound to its associated data."""

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
        """Open a sealed value, unwrapping its data key off the event loop only when one is needed."""

        wrapped, nonce, sealed = open(to_bytes(ciphertext))

        return unseal(await cls.async_unwrapped_key(wrapped), nonce, sealed, associated_data)


if sys.platform != "win32":
    os.register_at_fork(after_in_child=AWSAdapter.reset_after_fork)
