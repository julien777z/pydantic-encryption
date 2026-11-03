import struct

import pytest
from cryptography.exceptions import InvalidTag

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import (
    CIPHERTEXT_MAGIC,
    CIPHERTEXT_VERSION,
    HEADER_LENGTH,
    HEADER_PACK_FORMAT,
    NONCE_LENGTH,
    AWSAdapter,
)
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue
from tests.cases import FOREIGN_CONTEXT, PLAINTEXT_IDS, PLAINTEXTS, SEALED_CONTEXT
from tests.models.kms import KMS_DECRYPT_KEY_ARN, KMS_KEY_ARN, FakeSyncKMSClient


async def seal(plaintext: str | bytes | EncryptedValue, asynchronous: bool) -> EncryptedValue:
    """Seal a value under the shared context through the sync or async path."""

    if asynchronous:
        return await AWSAdapter.async_encrypt(plaintext, associated_data=SEALED_CONTEXT)

    return AWSAdapter.encrypt(plaintext, associated_data=SEALED_CONTEXT)


async def open_sealed(ciphertext: bytes | str, context: bytes, asynchronous: bool) -> str:
    """Open a value through the sync or async path."""

    if asynchronous:
        return await AWSAdapter.async_decrypt(ciphertext, associated_data=context)

    return AWSAdapter.decrypt(ciphertext, associated_data=context)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
class TestEnvelope:
    """Test the AWS KMS envelope: its format, its context binding and the key each half names."""

    @pytest.mark.parametrize("plaintext", PLAINTEXTS, ids=PLAINTEXT_IDS)
    async def test_round_trip(self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool, plaintext: str):
        """Test that a value opens back to itself under the context it was sealed with."""

        sealed = await seal(plaintext, asynchronous)

        assert await open_sealed(sealed, SEALED_CONTEXT, asynchronous) == plaintext

    async def test_text_ciphertext_opens_byte_for_byte(
        self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool
    ):
        """Test that a ciphertext passed as latin-1 text opens like its bytes."""

        sealed = await seal("secret data", asynchronous)

        assert (
            await open_sealed(bytes(sealed).decode("latin-1"), SEALED_CONTEXT, asynchronous) == "secret data"
        )

    async def test_header_names_format_and_version(
        self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool
    ):
        """Test that a sealed value starts with the envelope's magic byte and version."""

        sealed = await seal(b"secret data", asynchronous)

        assert bytes(sealed)[:2] == bytes([CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION])

    async def test_requests_aes_256_data_key(self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool):
        """Test that sealing asks KMS for a 256-bit data key under the configured key."""

        await seal(b"secret data", asynchronous)

        assert fake_sync_kms.generate_calls == [{"KeyId": KMS_KEY_ARN, "KeySpec": "AES_256"}]

    async def test_ciphertext_passes_through(self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool):
        """Test that sealing an existing ciphertext returns it without reaching KMS."""

        ciphertext = EncryptedValue(b"already-sealed")

        assert await seal(ciphertext, asynchronous) is ciphertext
        assert fake_sync_kms.generate_calls == []

    async def test_foreign_context_refused(self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool):
        """Test that a value lifted into another context fails to open there."""

        sealed = await seal("secret data", asynchronous)

        with pytest.raises(InvalidTag):
            await open_sealed(sealed, FOREIGN_CONTEXT, asynchronous)

    @pytest.mark.parametrize(
        ("ciphertext", "message"),
        [
            (b"\xc0\x01", "too short"),
            (b"\x01" + b"\x00" * 32, "Unrecognized ciphertext format"),
            (bytes([CIPHERTEXT_MAGIC, 0x99]) + b"\x00" * (HEADER_LENGTH + NONCE_LENGTH), "Unsupported"),
            (struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, 1024), "truncated"),
        ],
        ids=["short", "magic", "version", "truncated"],
    )
    async def test_malformed_envelope_refused(
        self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool, ciphertext: bytes, message: str
    ):
        """Test that an envelope with a bad header or missing bytes raises before reaching KMS."""

        with pytest.raises(ValueError, match=message):
            await open_sealed(ciphertext, SEALED_CONTEXT, asynchronous)

        assert fake_sync_kms.decrypt_calls == []

    @pytest.mark.parametrize(
        ("key_arn", "decrypt_key_arn", "expected_key_id"),
        [
            (KMS_KEY_ARN, None, KMS_KEY_ARN),
            (KMS_KEY_ARN, KMS_DECRYPT_KEY_ARN, KMS_DECRYPT_KEY_ARN),
            (None, None, None),
        ],
        ids=["shared-key", "decrypt-key", "unscoped"],
    )
    async def test_unwrap_names_configured_key(
        self,
        fake_sync_kms: FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
        asynchronous: bool,
        key_arn: str | None,
        decrypt_key_arn: str | None,
        expected_key_id: str | None,
    ):
        """Test that an unwrap names the decrypt key, else the shared key, else none for KMS to read."""

        sealed = await seal("secret data", asynchronous)

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", key_arn)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", decrypt_key_arn)

        assert await open_sealed(sealed, SEALED_CONTEXT, asynchronous) == "secret data"
        assert fake_sync_kms.decrypt_calls[-1].get("KeyId") == expected_key_id

    async def test_decrypt_only_configuration_refuses_sealing(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
    ):
        """Test that a decrypt-only key refuses to seal rather than sealing under nothing."""

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", KMS_DECRYPT_KEY_ARN)

        with pytest.raises(ValueError, match="decrypt-only"):
            await seal(b"secret data", asynchronous)
