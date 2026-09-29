import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import (
    CIPHERTEXT_MAGIC,
    HEADER_LENGTH,
    NONCE_LENGTH,
    AWSAdapter,
)
from pydantic_encryption.config import settings
from tests.kms import FakeSyncKMSClient, KMS_TEST_CONTEXT


class TestAWSAdapterDecrypt:
    """Test that decrypt() unwraps the data key via KMS and AES-GCM-decrypts the payload."""

    def test_encrypt_then_decrypt_round_trips(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt(encrypt(x)) returns x as a str."""

        sealed = AWSAdapter.encrypt("hello world", associated_data=KMS_TEST_CONTEXT)

        result = AWSAdapter.decrypt(sealed, associated_data=KMS_TEST_CONTEXT)

        assert result == "hello world"
        assert len(fake_sync_kms.decrypt_calls) == 1

    def test_decrypt_unwraps_each_data_key_once(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that values sealed under two data keys cost two KMS unwraps however often they are read."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        sealed_one = AWSAdapter.encrypt("first", associated_data=KMS_TEST_CONTEXT)
        sealed_two = AWSAdapter.encrypt("second", associated_data=KMS_TEST_CONTEXT)

        AWSAdapter.decrypt(sealed_one, associated_data=KMS_TEST_CONTEXT)
        AWSAdapter.decrypt(sealed_one, associated_data=KMS_TEST_CONTEXT)
        AWSAdapter.decrypt(sealed_two, associated_data=KMS_TEST_CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 2

    def test_decrypt_rejects_unrecognized_format(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises ValueError when the magic byte does not match."""

        bogus = b"\x01" + b"\x00" * 32

        with pytest.raises(ValueError, match="Unrecognized ciphertext format"):
            AWSAdapter.decrypt(bogus, associated_data=KMS_TEST_CONTEXT)

    def test_decrypt_rejects_unsupported_version(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypt() raises ValueError when the version byte is not supported."""

        unsupported = bytes([CIPHERTEXT_MAGIC, 0x99]) + b"\x00" * (HEADER_LENGTH + NONCE_LENGTH)

        with pytest.raises(ValueError, match="Unsupported"):
            AWSAdapter.decrypt(unsupported, associated_data=KMS_TEST_CONTEXT)

    def test_decrypt_passes_decrypt_arn_to_kms_when_configured(
        self,
        fake_sync_kms: FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        sealed = AWSAdapter.encrypt("payload", associated_data=KMS_TEST_CONTEXT)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        AWSAdapter.decrypt(sealed, associated_data=KMS_TEST_CONTEXT)

        assert fake_sync_kms.decrypt_calls[-1].get("KeyId") == "arn:aws:kms:us-east-1:000:key/dec"
