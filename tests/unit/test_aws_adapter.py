import struct
from typing import Any, Final

from botocore.config import Config
import pytest

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
from tests.kms import FakeSyncKMSClient, configure_kms_settings, reset_adapter_state

CONTEXT: Final[bytes] = b"tests.aws_adapter.payload"


class TestAWSAdapterEncrypt:
    """Test that encrypt() wraps a fresh data key under KMS and seals the plaintext with AES-GCM."""

    def test_encrypt_returns_encrypted_value_with_known_header(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that encrypt() emits an EncryptedValue starting with the format magic + version."""

        result = AWSAdapter.encrypt(b"plaintext-payload", associated_data=CONTEXT)

        assert isinstance(result, EncryptedValue)

        blob = bytes(result)
        assert blob[0] == CIPHERTEXT_MAGIC
        assert blob[1] == CIPHERTEXT_VERSION

    def test_encrypt_requests_an_aes_256_data_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypt() asks KMS for a 256-bit data key under the configured key."""

        AWSAdapter.encrypt(b"payload", associated_data=CONTEXT)

        assert fake_sync_kms.generate_calls == [
            {"KeyId": "arn:aws:kms:us-east-1:000:key/test", "KeySpec": "AES_256"}
        ]

    def test_encrypt_encodes_str_input(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypt() encodes a str plaintext to utf-8 before sealing."""

        AWSAdapter.encrypt("plain-str", associated_data=CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 1

    def test_encrypt_passthrough_for_already_encrypted_value(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypt() returns an existing EncryptedValue unchanged without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = AWSAdapter.encrypt(already_encrypted, associated_data=CONTEXT)

        assert result is already_encrypted
        assert fake_sync_kms.generate_calls == []


class TestAWSAdapterDecrypt:
    """Test that decrypt() unwraps the data key via KMS and AES-GCM-decrypts the payload."""

    def test_encrypt_then_decrypt_round_trips(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt(encrypt(x)) returns x as a str."""

        sealed = AWSAdapter.encrypt("hello world", associated_data=CONTEXT)

        result = AWSAdapter.decrypt(sealed, associated_data=CONTEXT)

        assert result == "hello world"
        assert len(fake_sync_kms.decrypt_calls) == 1

    def test_decrypt_unwraps_each_data_key_once(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that values sealed under two data keys cost two KMS unwraps however often they are read."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        sealed_one = AWSAdapter.encrypt("first", associated_data=CONTEXT)
        sealed_two = AWSAdapter.encrypt("second", associated_data=CONTEXT)

        AWSAdapter.decrypt(sealed_one, associated_data=CONTEXT)
        AWSAdapter.decrypt(sealed_one, associated_data=CONTEXT)
        AWSAdapter.decrypt(sealed_two, associated_data=CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 2

    def test_decrypt_rejects_unrecognized_format(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises ValueError when the magic byte does not match."""

        bogus = b"\x01" + b"\x00" * 32

        with pytest.raises(ValueError, match="Unrecognized ciphertext format"):
            AWSAdapter.decrypt(bogus, associated_data=CONTEXT)

    def test_decrypt_rejects_unsupported_version(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises ValueError when the version byte is not supported."""

        unsupported = bytes([CIPHERTEXT_MAGIC, 0x99]) + b"\x00" * (HEADER_LENGTH + NONCE_LENGTH)

        with pytest.raises(ValueError, match="Unsupported"):
            AWSAdapter.decrypt(unsupported, associated_data=CONTEXT)

    def test_decrypt_passes_decrypt_arn_to_kms_when_configured(
        self,
        fake_sync_kms: FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        sealed = AWSAdapter.encrypt("payload", associated_data=CONTEXT)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        AWSAdapter.decrypt(sealed, associated_data=CONTEXT)

        assert fake_sync_kms.decrypt_calls[-1]["KeyId"] == "arn:aws:kms:us-east-1:000:key/dec"


class TestAWSAdapterAsync:
    """Test that async_encrypt / async_decrypt seal and open values, reaching KMS off the event loop."""

    @pytest.mark.asyncio
    async def test_async_encrypt_then_async_decrypt_round_trips(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that async_decrypt(async_encrypt(x)) returns x as a str."""

        sealed = await AWSAdapter.async_encrypt("hello async", associated_data=CONTEXT)

        result = await AWSAdapter.async_decrypt(sealed, associated_data=CONTEXT)

        assert result == "hello async"
        assert len(fake_sync_kms.generate_calls) == 1
        assert len(fake_sync_kms.decrypt_calls) == 1

    @pytest.mark.asyncio
    async def test_async_encrypt_passthrough_for_already_encrypted_value(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that async_encrypt() returns an existing EncryptedValue without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = await AWSAdapter.async_encrypt(already_encrypted, associated_data=CONTEXT)

        assert result is already_encrypted
        assert fake_sync_kms.generate_calls == []

    @pytest.mark.asyncio
    async def test_async_decrypt_passes_decrypt_arn_when_configured(
        self,
        fake_sync_kms: FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that async_decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        sealed = await AWSAdapter.async_encrypt("payload", associated_data=CONTEXT)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        await AWSAdapter.async_decrypt(sealed, associated_data=CONTEXT)

        assert fake_sync_kms.decrypt_calls[-1]["KeyId"] == "arn:aws:kms:us-east-1:000:key/dec"


class TestAWSAdapterValidation:
    """Test the ciphertext-format guards on the decrypt path."""

    def test_kms_client_build_raises_when_settings_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that the lazy KMS client builder rejects unset AWS_KMS settings at use time."""

        reset_adapter_state()

        for attr in (
            "AWS_KMS_KEY_ARN",
            "AWS_KMS_ENCRYPT_KEY_ARN",
            "AWS_KMS_DECRYPT_KEY_ARN",
            "AWS_KMS_REGION",
            "AWS_KMS_ACCESS_KEY_ID",
            "AWS_KMS_SECRET_ACCESS_KEY",
        ):
            monkeypatch.setattr(settings, attr, None)

        with pytest.raises(ValueError, match="AWS_KMS_REGION"):
            AWSAdapter.encrypt(b"payload", associated_data=CONTEXT)

    def test_decrypt_accepts_str_ciphertext_via_latin1(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() coerces a str ciphertext to bytes 1:1 (latin-1) for the EncryptionAdapter contract."""

        sealed = AWSAdapter.encrypt("hello world", associated_data=CONTEXT)

        as_str = bytes(sealed).decode("latin-1")

        result = AWSAdapter.decrypt(as_str, associated_data=CONTEXT)

        assert result == "hello world"

    def test_decrypt_rejects_truncated_ciphertext(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises when the input is shorter than the envelope header."""

        with pytest.raises(ValueError, match="too short"):
            AWSAdapter.decrypt(b"\xc0\x01", associated_data=CONTEXT)

    def test_decrypt_rejects_truncated_payload(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises when the header announces more bytes than the blob carries."""

        # Header claims a 1024-byte wrapped key but the blob has no payload.
        truncated = struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, 1024)

        with pytest.raises(ValueError, match="truncated"):
            AWSAdapter.decrypt(truncated, associated_data=CONTEXT)


class TestAWSAdapterLazyInit:
    """Test the lazy boto3 client construction path."""

    def test_sync_kms_builds_boto3_client_on_first_use(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that the first call to ``encrypt()`` builds a boto3 KMS client and caches it."""

        reset_adapter_state()

        configure_kms_settings(monkeypatch)

        captured_kwargs: list[dict[str, Any]] = []

        def fake_boto3_client(service: str, **kwargs: Any) -> Any:
            captured_kwargs.append({"service": service, **kwargs})
            return FakeSyncKMSClient()

        monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.boto3.client", fake_boto3_client)

        AWSAdapter.encrypt(b"payload", associated_data=CONTEXT)

        assert len(captured_kwargs) == 1
        assert captured_kwargs[0]["service"] == "kms"
        assert captured_kwargs[0]["region_name"] == "us-east-1"
        assert isinstance(captured_kwargs[0]["config"], Config)
        assert captured_kwargs[0]["config"].connect_timeout == 2
        assert captured_kwargs[0]["config"].read_timeout == 5
        assert captured_kwargs[0]["config"].retries == {"mode": "standard", "total_max_attempts": 2}
        assert AWSAdapter._sync_client is not None

        AWSAdapter.encrypt(b"payload-2", associated_data=CONTEXT)

        assert len(captured_kwargs) == 1

        reset_adapter_state()
