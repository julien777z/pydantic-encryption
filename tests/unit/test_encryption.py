from pydantic_encryption.adapters.encryption.fernet import fernet_encrypt
from tests.models import User, UserDecrypt


class TestUnitEncryptionModel:
    """Test basic functionality of pydantic-encryption with mocked models."""

    def test_encrypt_field(self, mock_basic_user: User):
        """Test encrypting fields with EncryptField annotation."""

        assert mock_basic_user.username == "user1"  # Not encrypted

        assert getattr(mock_basic_user.address, "encrypted", False)

    def test_double_encrypt_fails(self, mock_basic_user: User):
        """Test double encrypting fails."""

        old_address = mock_basic_user.address

        mock_basic_user.address = fernet_encrypt(mock_basic_user.address)

        assert mock_basic_user.address == old_address

    def test_decrypt_field(self, mock_basic_user: User):
        """Test decrypting fields with DecryptField annotation."""

        encrypted_data = mock_basic_user.model_dump()

        decrypted_user = UserDecrypt(**encrypted_data)

        assert decrypted_user.username == "user1"
        assert not getattr(decrypted_user.address, "encrypted", False)

    def test_disable_encryption(self, mock_user_disabled_encryption: User):
        """Test disabling encryption."""

        assert not getattr(mock_user_disabled_encryption.address, "encrypted", False)
