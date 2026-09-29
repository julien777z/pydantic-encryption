import struct

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import (
    CIPHERTEXT_MAGIC,
    CIPHERTEXT_VERSION,
    HEADER_PACK_FORMAT,
    AWSAdapter,
)
from pydantic_encryption.config import settings
from tests.kms import FakeSyncKMSClient, KMS_TEST_CONTEXT, reset_adapter_state


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
            AWSAdapter.encrypt(b"payload", associated_data=KMS_TEST_CONTEXT)

    def test_decrypt_accepts_str_ciphertext_via_latin1(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() coerces a str ciphertext to bytes 1:1 (latin-1) for the EncryptionAdapter contract."""

        sealed = AWSAdapter.encrypt("hello world", associated_data=KMS_TEST_CONTEXT)

        as_str = bytes(sealed).decode("latin-1")

        result = AWSAdapter.decrypt(as_str, associated_data=KMS_TEST_CONTEXT)

        assert result == "hello world"

    def test_decrypt_rejects_truncated_ciphertext(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises when the input is shorter than the envelope header."""

        with pytest.raises(ValueError, match="too short"):
            AWSAdapter.decrypt(b"\xc0\x01", associated_data=KMS_TEST_CONTEXT)

    def test_decrypt_rejects_truncated_payload(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises when the header announces more bytes than the blob carries."""

        truncated = struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, 1024)

        with pytest.raises(ValueError, match="truncated"):
            AWSAdapter.decrypt(truncated, associated_data=KMS_TEST_CONTEXT)
