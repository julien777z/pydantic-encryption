import pytest
from cryptography.exceptions import InvalidTag

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from tests.kms import KMS_FOREIGN_CONTEXT, KMS_TEST_CONTEXT
from tests.models.kms import FakeSyncKMSClient


class TestAWSCiphertextContextBinding:
    """Test that an AWS ciphertext only opens under the context it was sealed with."""

    def test_decrypt_under_a_different_context_fails(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that a value lifted into another context fails to open there."""

        sealed = AWSAdapter.encrypt("secret data", associated_data=KMS_TEST_CONTEXT)

        with pytest.raises(InvalidTag):
            AWSAdapter.decrypt(sealed, associated_data=KMS_FOREIGN_CONTEXT)

    @pytest.mark.asyncio
    async def test_async_decrypt_under_a_different_context_fails(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that the async path rejects a ciphertext from another context too."""

        sealed = await AWSAdapter.async_encrypt("secret data", associated_data=KMS_TEST_CONTEXT)

        with pytest.raises(InvalidTag):
            await AWSAdapter.async_decrypt(sealed, associated_data=KMS_FOREIGN_CONTEXT)

    @pytest.mark.parametrize(
        "plaintext",
        ["", "secret data", "日本語 한국어 العربية 🎉🔒", '!@#$%^&*()_+-={}[]|\\:";<>?,./~`'],
        ids=["empty", "ascii", "unicode", "punctuation"],
    )
    def test_round_trip_under_the_matching_context(self, fake_sync_kms: FakeSyncKMSClient, plaintext: str):
        """Test that decrypt returns the plaintext when handed the context encrypt was given."""

        sealed = AWSAdapter.encrypt(plaintext, associated_data=KMS_TEST_CONTEXT)

        assert AWSAdapter.decrypt(sealed, associated_data=KMS_TEST_CONTEXT) == plaintext

    @pytest.mark.asyncio
    async def test_async_round_trip_under_the_matching_context(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that the async path round trips under one context."""

        sealed = await AWSAdapter.async_encrypt("secret data", associated_data=KMS_TEST_CONTEXT)

        assert await AWSAdapter.async_decrypt(sealed, associated_data=KMS_TEST_CONTEXT) == "secret data"
