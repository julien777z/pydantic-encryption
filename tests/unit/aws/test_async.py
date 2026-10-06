import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import FakeSyncKMSClient


class TestAWSAdapterAsync:
    """Test that async_encrypt / async_decrypt seal and open values, reaching KMS off the event loop."""

    @pytest.mark.asyncio
    async def test_async_encrypt_then_async_decrypt_round_trips(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that async_decrypt(async_encrypt(x)) returns x as a str."""

        sealed = await AWSAdapter.async_encrypt("hello async", associated_data=KMS_TEST_CONTEXT)

        result = await AWSAdapter.async_decrypt(sealed, associated_data=KMS_TEST_CONTEXT)

        assert result == "hello async"
        assert len(fake_sync_kms.generate_calls) == 1
        assert len(fake_sync_kms.decrypt_calls) == 1

    @pytest.mark.asyncio
    async def test_async_encrypt_passthrough_for_already_encrypted_value(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that async_encrypt() returns an existing EncryptedValue without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = await AWSAdapter.async_encrypt(already_encrypted, associated_data=KMS_TEST_CONTEXT)

        assert result is already_encrypted
        assert fake_sync_kms.generate_calls == []

    @pytest.mark.asyncio
    async def test_async_decrypt_passes_decrypt_arn_when_configured(
        self,
        fake_sync_kms: FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that async_decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        sealed = await AWSAdapter.async_encrypt("payload", associated_data=KMS_TEST_CONTEXT)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        await AWSAdapter.async_decrypt(sealed, associated_data=KMS_TEST_CONTEXT)

        assert fake_sync_kms.decrypt_calls[-1].get("KeyId") == "arn:aws:kms:us-east-1:000:key/dec"
