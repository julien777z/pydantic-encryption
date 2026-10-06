import asyncio

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.factories import User
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import FakeSyncKMSClient


class TestUnwrappedKeyCache:
    """Test that reading many values does not unwrap their data key once per value."""

    def test_values_sharing_a_data_key_unwrap_it_once(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that a data key is unwrapped once however many values it sealed."""

        ciphertexts = [
            AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT) for index in range(20)
        ]

        for ciphertext in ciphertexts:
            AWSAdapter.decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 1

    @pytest.mark.asyncio
    async def test_concurrent_reads_share_one_unwrap(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that decrypts racing on an unwrapped key share one KMS call."""

        ciphertexts = [
            await AWSAdapter.async_encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)
            for index in range(20)
        ]

        await asyncio.gather(
            *(
                AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)
                for ciphertext in ciphertexts
            )
        )

        assert len(fake_sync_kms.decrypt_calls) == 1

    def test_cache_is_bounded(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the unwrapped-key cache evicts rather than growing without limit."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE", 2)

        ciphertexts = [
            AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT) for index in range(4)
        ]

        for ciphertext in ciphertexts:
            AWSAdapter.decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)

        assert len(AWSAdapter.unwrapped_keys) == 2

    @pytest.mark.asyncio
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_expired_key_unwrapped_again(
        self,
        fake_sync_kms: FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
        asynchronous: bool,
        user: User,
    ) -> None:
        """Test that an unwrapped key past its retention goes back to KMS."""

        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS", 0)
        ciphertext = AWSAdapter.encrypt(user.username, associated_data=KMS_TEST_CONTEXT)

        for _ in range(2):
            if asynchronous:
                plaintext = await AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)
            else:
                plaintext = AWSAdapter.decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)

            assert plaintext == user.username

        assert len(fake_sync_kms.decrypt_calls) == 2
