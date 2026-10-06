import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, AWSAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.models.kms import DataKeyGenerateRequest
from pydantic_encryption.types import EncryptedValue
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import FakeSyncKMSClient


class TestAWSAdapterEncrypt:
    """Test that encrypt() wraps a fresh data key under KMS and seals the plaintext with AES-GCM."""

    def test_encrypt_returns_encrypted_value_with_known_header(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that encrypt() emits an EncryptedValue starting with the format magic + version."""

        result = AWSAdapter.encrypt(b"plaintext-payload", associated_data=KMS_TEST_CONTEXT)

        assert isinstance(result, EncryptedValue)

        blob = bytes(result)
        assert blob[0] == CIPHERTEXT_MAGIC
        assert blob[1] == CIPHERTEXT_VERSION

    def test_encrypt_requests_an_aes_256_data_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypt() asks KMS for a 256-bit data key under the configured key."""

        AWSAdapter.encrypt(b"payload", associated_data=KMS_TEST_CONTEXT)

        assert settings.AWS_KMS_KEY_ARN is not None
        assert fake_sync_kms.generate_calls == [
            DataKeyGenerateRequest(KeyId=settings.AWS_KMS_KEY_ARN, KeySpec="AES_256")
        ]

    def test_encrypt_encodes_str_input(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypt() encodes a str plaintext to utf-8 before sealing."""

        AWSAdapter.encrypt("plain-str", associated_data=KMS_TEST_CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 1

    def test_encrypt_passthrough_for_already_encrypted_value(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypt() returns an existing EncryptedValue unchanged without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = AWSAdapter.encrypt(already_encrypted, associated_data=KMS_TEST_CONTEXT)

        assert result is already_encrypted
        assert fake_sync_kms.generate_calls == []
