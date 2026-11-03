import asyncio

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.cases import SEALED_CONTEXT
from tests.models.kms import FakeSyncKMSClient
from tests.unit.utils import ASYNC_PATHS, call_path, seal_values


@pytest.mark.asyncio
class TestUnwrappedKeyCache:
    """Test that reading many values does not unwrap their data key once per value."""

    async def test_shared_data_key_unwrapped_once(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that a data key is unwrapped once however many values it sealed."""

        for ciphertext in await seal_values(20):
            AWSAdapter.decrypt(ciphertext, associated_data=SEALED_CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 1

    async def test_concurrent_reads_share_one_unwrap(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that decrypts racing on one cold data key share one KMS call."""

        ciphertexts = await seal_values(20, asynchronous=True)

        await asyncio.gather(
            *(
                AWSAdapter.async_decrypt(ciphertext, associated_data=SEALED_CONTEXT)
                for ciphertext in ciphertexts
            )
        )

        assert len(fake_sync_kms.decrypt_calls) == 1

    async def test_least_recently_used_key_evicted(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ):
        """Test that a full cache evicts the key read longest ago, keeping a recently read one."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE", 2)
        first, second, third = await seal_values(3)

        for ciphertext in (first, second, first, third, first):
            AWSAdapter.decrypt(ciphertext, associated_data=SEALED_CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 3
        assert len(AWSAdapter.unwrapped_keys) == 2

    @ASYNC_PATHS
    async def test_expired_key_unwrapped_again(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
    ):
        """Test that an unwrapped key past its retention goes back to KMS."""

        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS", 0)
        ciphertext = AWSAdapter.encrypt("secret data", associated_data=SEALED_CONTEXT)

        for _ in range(2):
            assert (
                await call_path(
                    asynchronous,
                    AWSAdapter.decrypt,
                    AWSAdapter.async_decrypt,
                    ciphertext,
                    associated_data=SEALED_CONTEXT,
                )
                == "secret data"
            )

        assert len(fake_sync_kms.decrypt_calls) == 2

    async def test_expired_key_dropped_without_further_reads(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ):
        """Test that an unwrapped key leaves memory when it expires, not when it is next looked up."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS", 0.05)
        ciphertext = AWSAdapter.encrypt("secret data", associated_data=SEALED_CONTEXT)

        AWSAdapter.decrypt(ciphertext, associated_data=SEALED_CONTEXT)
        timer = AWSAdapter.expiry_timer

        assert len(AWSAdapter.unwrapped_keys) == 1
        assert timer is not None

        timer.join(timeout=5)

        assert len(AWSAdapter.unwrapped_keys) == 0
