from tests.mocks.mock_users import User, mock_basic_user, mock_user_disabled_encryption
from pydantic_encryption.lib.adapters.hashing.argon2 import argon2_hash_data


class TestHashing:
    """Test basic functionality of pydantic-encryption."""

    def test_hash_field(self, mock_basic_user: User):
        """Test hashing fields with HashField annotation."""

        assert mock_basic_user.username == "user1"  # Not encrypted

        assert getattr(mock_basic_user.password, "is_hashed", False)

    def test_double_hash_fails(self, mock_basic_user: User):
        """Test double hashing fails."""

        old_password = mock_basic_user.password

        mock_basic_user.password = argon2_hash_data(mock_basic_user.password)

        assert mock_basic_user.password == old_password

    def test_disable_hashing(self, mock_user_disabled_encryption: User):
        """Test disabling hashing."""

        assert not getattr(mock_user_disabled_encryption.password, "is_hashed", False)
