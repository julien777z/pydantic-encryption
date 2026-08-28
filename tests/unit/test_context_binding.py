import pytest
from cryptography.exceptions import InvalidTag
from cryptography.fernet import InvalidToken

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from tests.factories import User
from tests.kms import FakeAsyncKMSClient, FakeSyncKMSClient

COLUMN_CONTEXT = b"tests.context_binding.first_column"
OTHER_COLUMN_CONTEXT = b"tests.context_binding.second_column"


class TestAWSCiphertextContextBinding:
    """Test that an AWS ciphertext only opens under the context it was sealed with."""

    def test_decrypt_under_a_different_context_fails(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that a value lifted into another context fails to open there."""

        sealed = AWSAdapter.encrypt("secret data", associated_data=COLUMN_CONTEXT)

        with pytest.raises(InvalidTag):
            AWSAdapter.decrypt(sealed, associated_data=OTHER_COLUMN_CONTEXT)

    @pytest.mark.asyncio
    async def test_async_decrypt_under_a_different_context_fails(self, fake_async_kms: FakeAsyncKMSClient):
        """Test that the async path rejects a ciphertext from another context too."""

        sealed = await AWSAdapter.async_encrypt("secret data", associated_data=COLUMN_CONTEXT)

        with pytest.raises(InvalidTag):
            await AWSAdapter.async_decrypt(sealed, associated_data=OTHER_COLUMN_CONTEXT)

    @pytest.mark.parametrize(
        "plaintext",
        ["", "secret data", "日本語 한국어 العربية 🎉🔒", '!@#$%^&*()_+-={}[]|\\:";<>?,./~`'],
        ids=["empty", "ascii", "unicode", "punctuation"],
    )
    def test_round_trip_under_the_matching_context(self, fake_sync_kms: FakeSyncKMSClient, plaintext: str):
        """Test that decrypt returns the plaintext when handed the context encrypt was given."""

        sealed = AWSAdapter.encrypt(plaintext, associated_data=COLUMN_CONTEXT)

        assert AWSAdapter.decrypt(sealed, associated_data=COLUMN_CONTEXT) == plaintext

    @pytest.mark.asyncio
    async def test_async_round_trip_under_the_matching_context(self, fake_async_kms: FakeAsyncKMSClient):
        """Test that the async path round trips under one context."""

        sealed = await AWSAdapter.async_encrypt("secret data", associated_data=COLUMN_CONTEXT)

        assert await AWSAdapter.async_decrypt(sealed, associated_data=COLUMN_CONTEXT) == "secret data"


class TestModelFieldContext:
    """Test that model fields bind their ciphertexts to the model and field they belong to."""

    def test_field_context_names_the_model_and_field(self, user: User):
        """Test that a field's context spells out its module, class, and field name."""

        assert user.field_context("address") == f"{User.__module__}.User.address".encode("utf-8")

    def test_field_context_differs_per_field(self, user: User):
        """Test that two fields of one model bind to different contexts."""

        assert user.field_context("address") != user.field_context("username")

    def test_encrypted_field_does_not_open_under_another_field_context(self, user: User):
        """Test that a model field's ciphertext fails to open under a sibling field's context."""

        with pytest.raises(InvalidToken):
            FernetAdapter.decrypt(user.address, associated_data=user.field_context("username"))
