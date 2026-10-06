import asyncio

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import FakeSyncKMSClient


class TestDataKeyReuse:
    """Test that one KMS data key seals many values."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_many_values_share_one_generated_data_key(
        self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool
    ) -> None:
        """Test that encrypting many values calls KMS once rather than once per value."""

        for index in range(50):
            if asynchronous:
                await AWSAdapter.async_encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)
            else:
                AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 1

    @pytest.mark.asyncio
    async def test_values_racing_a_cold_cache_share_one_key(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that encrypts arriving together mint one key between them."""

        await asyncio.gather(
            *(
                AWSAdapter.async_encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)
                for index in range(50)
            )
        )

        assert len(fake_sync_kms.generate_calls) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_values_round_trip_through_the_shared_key(
        self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool
    ) -> None:
        """Test that a value sealed under a reused key opens back to itself."""

        ciphertexts = [
            (
                await AWSAdapter.async_encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)
                if asynchronous
                else AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)
            )
            for index in range(5)
        ]

        decrypted = [
            (
                await AWSAdapter.async_decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)
                if asynchronous
                else AWSAdapter.decrypt(ciphertext, associated_data=KMS_TEST_CONTEXT)
            )
            for ciphertext in ciphertexts
        ]

        assert decrypted == [f"value-{index}" for index in range(5)]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_spent_use_budget_generates_fresh_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
    ) -> None:
        """Test that the use bound is enforced instead of holding one key indefinitely."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 4)

        for index in range(9):
            if asynchronous:
                await AWSAdapter.async_encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)
            else:
                AWSAdapter.encrypt(f"value-{index}", associated_data=KMS_TEST_CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 3

    @pytest.mark.asyncio
    @pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
    async def test_expired_key_generates_fresh_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
    ) -> None:
        """Test that a data key past its maximum age is replaced."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_AGE_SECONDS", 0)

        for value in ("first", "second"):
            if asynchronous:
                await AWSAdapter.async_encrypt(value, associated_data=KMS_TEST_CONTEXT)
            else:
                AWSAdapter.encrypt(value, associated_data=KMS_TEST_CONTEXT)

        assert len(fake_sync_kms.generate_calls) == 2

    def test_key_material_is_kept_out_of_representations(self, fake_sync_kms: FakeSyncKMSClient) -> None:
        """Test that a held data key never renders its plaintext in a repr."""

        AWSAdapter.encrypt("value", associated_data=KMS_TEST_CONTEXT)
        held = AWSAdapter.encrypt_key

        assert held is not None
        assert "plaintext" not in repr(held)
        assert held.plaintext.hex() not in repr(held)
