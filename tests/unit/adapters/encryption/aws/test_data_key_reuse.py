import asyncio

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.cases import SEALED_CONTEXT
from tests.models.kms import FakeSyncKMSClient
from tests.unit.utils import ASYNC_PATHS, seal_values


@pytest.mark.asyncio
class TestDataKeyReuse:
    """Test that one KMS data key seals many values, within its use and age bounds."""

    @ASYNC_PATHS
    async def test_values_share_one_data_key(self, fake_sync_kms: FakeSyncKMSClient, asynchronous: bool):
        """Test that sealing many values calls KMS once rather than once per value."""

        await seal_values(50, asynchronous)

        assert len(fake_sync_kms.generate_calls) == 1

    async def test_racing_values_share_one_data_key(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that values sealed together on a cold cache mint one key between them."""

        await asyncio.gather(
            *(
                AWSAdapter.async_encrypt(f"value-{index}", associated_data=SEALED_CONTEXT)
                for index in range(50)
            )
        )

        assert len(fake_sync_kms.generate_calls) == 1

    @ASYNC_PATHS
    async def test_spent_use_budget_generates_fresh_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
    ):
        """Test that a key stops sealing once it has sealed its maximum number of values."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_USES", 4)

        await seal_values(9, asynchronous)

        assert len(fake_sync_kms.generate_calls) == 3

    @ASYNC_PATHS
    async def test_expired_key_generates_fresh_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
    ):
        """Test that a key past its maximum age is replaced."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_AGE_SECONDS", 0)

        await seal_values(2, asynchronous)

        assert len(fake_sync_kms.generate_calls) == 2

    async def test_expired_key_dropped_without_further_use(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ):
        """Test that a key leaves memory when it expires, not when the next value is sealed."""

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_MAX_AGE_SECONDS", 0.05)

        await seal_values(1)
        timer = AWSAdapter.expiry_timer

        assert AWSAdapter.encrypt_key is not None
        assert timer is not None

        timer.join(timeout=5)

        assert AWSAdapter.encrypt_key is None

    async def test_key_material_kept_out_of_repr(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that a held data key renders neither its plaintext nor its wrapped form in a repr."""

        await seal_values(1)
        held = AWSAdapter.encrypt_key

        assert held is not None
        assert held.plaintext.hex() not in repr(held)
        assert "plaintext" not in repr(held)
        assert "wrapped" not in repr(held)
