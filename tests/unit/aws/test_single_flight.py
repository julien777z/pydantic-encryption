from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from tests.kms import FakeSyncKMSClient, KMS_TEST_CONTEXT, SlowFakeKMS


class TestSingleFlight:
    """Test that threads racing a cold cache share one KMS call between them."""

    def test_racing_threads_mint_one_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that concurrent sync encrypts on a cold cache generate one key, not one each."""

        slow = SlowFakeKMS()
        monkeypatch.setattr(AWSAdapter, "_sync_client", slow)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda index: AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT),
                    range(8),
                )
            )

        assert len(slow.generate_calls) == 1

    def test_threads_racing_a_cold_key_unwrap_it_once(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that concurrent sync decrypts of one cold data key unwrap it once, not once each."""

        slow = SlowFakeKMS()
        monkeypatch.setattr(AWSAdapter, "_sync_client", slow)
        ciphertexts = [
            AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT) for index in range(8)
        ]

        with ThreadPoolExecutor(max_workers=8) as pool:
            decrypted = list(
                pool.map(
                    lambda ciphertext: AWSAdapter.decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT),
                    ciphertexts,
                )
            )

        assert decrypted == [f"value-{index}" for index in range(8)]
        assert len(slow.decrypt_calls) == 1
