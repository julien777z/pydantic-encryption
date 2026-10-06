import pytest
from cryptography.fernet import InvalidToken

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.context import derive_field_context
from tests.factories import User


class TestModelFieldContext:
    """Test that model fields bind their ciphertexts to the model and field they belong to."""

    def test_field_context_names_the_model_and_field(self, user: User):
        """Test that a field's context spells out its module, class, and field name."""

        assert user.field_context("address") == derive_field_context(User.__module__, "User", "address")

    def test_field_context_differs_per_field(self, user: User):
        """Test that two fields of one model bind to different contexts."""

        assert user.field_context("address") != user.field_context("username")

    def test_encrypted_field_does_not_open_under_another_field_context(self, user: User):
        """Test that a model field's ciphertext fails to open under a sibling field's context."""

        with pytest.raises(InvalidToken):
            FernetAdapter.decrypt(user.address, associated_data=user.field_context("username"))
