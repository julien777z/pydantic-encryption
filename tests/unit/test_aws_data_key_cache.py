import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Final

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.kms import FakeSyncKMSClient

CONTEXT: Final[bytes] = b"tests.aws_data_key_cache"


class TestDataKeyReuse:
    """Test that one KMS data key seals many values."""

    def test_many_values_share_one_generated_data_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypting many values calls KMS once rather than once per value."""

        for index in range(50):
            AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 1

    @pytest.mark.asyncio
    async def test_values_racing_a_cold_cache_share_one_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypts arriving together mint one key between them."""

        await asyncio.gather(
            *(AWSAdapter.async_encrypt(f"value-{index}", associated_data=CONTEXT) for index in range(50))
        )

        assert len(fake_sync_kms.generate_calls) == 1

    def test_values_round_trip_through_the_shared_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that a value sealed under a reused key opens back to itself."""

        ciphertexts = [AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT) for index in range(5)]

        decrypted = [AWSAdapter.decrypt(ciphertext, associated_data=CONTEXT) for ciphertext in ciphertexts]

        assert decrypted == [f"value-{index}" for index in range(5)]

    def test_a_spent_use_budget_generates_a_fresh_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the use bound is enforced instead of holding one key indefinitely."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 4)

        for index in range(9):
            AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 3

    def test_an_expired_key_generates_a_fresh_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a data key past its maximum age is replaced."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_AGE_SECONDS", 0)

        AWSAdapter.encrypt("first", associated_data=CONTEXT)
        AWSAdapter.encrypt("second", associated_data=CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 2

    def test_key_material_is_kept_out_of_representations(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that a held data key never renders its plaintext in a repr."""

        AWSAdapter.encrypt("value", associated_data=CONTEXT)
        held = AWSAdapter.encrypt_key

        assert held is not None
        assert "plaintext" not in repr(held)
        assert held.plaintext.hex() not in repr(held)


class SlowFakeKMS(FakeSyncKMSClient):
    """Fake KMS whose calls take long enough for racing threads to pile up behind one."""

    def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        time.sleep(0.05)

        return super().generate_data_key(**kwargs)

    def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        time.sleep(0.05)

        return super().decrypt(**kwargs)


class TestSingleFlight:
    """Test that threads racing a cold cache share one KMS call between them."""

    def test_threads_racing_a_cold_cache_mint_one_data_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that concurrent sync encrypts on a cold cache generate one key, not one each."""

        slow = SlowFakeKMS()
        AWSAdapter._sync_client = slow

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda index: AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT), range(8)
                )
            )

        assert len(slow.generate_calls) == 1

    def test_threads_racing_a_cold_key_unwrap_it_once(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that concurrent sync decrypts of one cold data key unwrap it once, not once each."""

        slow = SlowFakeKMS()
        AWSAdapter._sync_client = slow
        ciphertexts = [AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT) for index in range(8)]

        with ThreadPoolExecutor(max_workers=8) as pool:
            decrypted = list(
                pool.map(
                    lambda ciphertext: AWSAdapter.decrypt(ciphertext, associated_data=CONTEXT), ciphertexts
                )
            )

        assert decrypted == [f"value-{index}" for index in range(8)]
        assert len(slow.decrypt_calls) == 1


class TestUnwrappedKeyCache:
    """Test that reading many values does not unwrap their data key once per value."""

    def test_values_sharing_a_data_key_unwrap_it_once(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that a data key is unwrapped once however many values it sealed."""

        ciphertexts = [AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT) for index in range(20)]

        for ciphertext in ciphertexts:
            AWSAdapter.decrypt(ciphertext, associated_data=CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 1

    @pytest.mark.asyncio
    async def test_concurrent_reads_of_a_cold_key_share_one_unwrap(
        self, fake_sync_kms: FakeSyncKMSClient
    ) -> None:
        """Test that decrypts racing on an unwrapped key share one KMS call."""

        ciphertexts = [
            await AWSAdapter.async_encrypt(f"value-{index}", associated_data=CONTEXT) for index in range(20)
        ]

        await asyncio.gather(
            *(AWSAdapter.async_decrypt(ciphertext, associated_data=CONTEXT) for ciphertext in ciphertexts)
        )

        assert len(fake_sync_kms.decrypt_calls) == 1

    def test_the_unwrapped_key_cache_is_bounded(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the unwrapped-key cache evicts rather than growing without limit."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 1)
        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_CACHE_SIZE", 2)

        ciphertexts = [AWSAdapter.encrypt(f"value-{index}", associated_data=CONTEXT) for index in range(4)]

        for ciphertext in ciphertexts:
            AWSAdapter.decrypt(ciphertext, associated_data=CONTEXT)

        assert len(AWSAdapter.unwrapped_keys) == 2

    def test_an_expired_unwrapped_key_is_unwrapped_again(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that an unwrapped key past its retention goes back to KMS."""

        monkeypatch.setattr(settings, "AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS", 0)
        ciphertext = AWSAdapter.encrypt("value", associated_data=CONTEXT)

        AWSAdapter.decrypt(ciphertext, associated_data=CONTEXT)
        AWSAdapter.decrypt(ciphertext, associated_data=CONTEXT)

        assert len(fake_sync_kms.decrypt_calls) == 2
