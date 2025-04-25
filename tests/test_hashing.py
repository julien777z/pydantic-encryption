from tests.mocks.mock_users import (
    User,
    mock_basic_user,
    mock_user_disabled_encryption,
)
from tests.test_utils import is_hashed


class TestHashing:
    """Test basic functionality of pydantic-encryption."""

    def test_hash_field(self, mock_basic_user: User):
        """Test hashing fields with HashField annotation."""

        assert mock_basic_user.username == "user1"  # Not encrypted
        assert is_hashed(mock_basic_user.password)

    def test_disable_hashing(self, mock_user_disabled_encryption: User):
        """Test disabling hashing."""

        assert not is_hashed(mock_user_disabled_encryption.password)
