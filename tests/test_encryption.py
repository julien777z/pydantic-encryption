from tests.mocks.mock_users import (
    User,
    UserDecrypt,
    mock_basic_user,
    mock_user_disabled_encryption,
)
from tests.test_utils import is_encrypted


class TestEncryption:
    """Test basic functionality of pydantic-encryption."""

    def test_encrypt_field(self, mock_basic_user: User):
        """Test encrypting fields with EncryptField annotation."""

        assert mock_basic_user.username == "user1"  # Not encrypted
        assert is_encrypted(mock_basic_user.address)

    def test_decrypt_field(self, mock_basic_user: User):
        """Test decrypting fields with DecryptField annotation."""

        encrypted_data = mock_basic_user.model_dump()

        decrypted_user = UserDecrypt(**encrypted_data)

        assert decrypted_user.username == "user1"
        assert not is_encrypted(decrypted_user.address)

    def test_disable_encryption(self, mock_user_disabled_encryption: User):
        """Test disabling encryption."""

        assert not is_encrypted(mock_user_disabled_encryption.address)
