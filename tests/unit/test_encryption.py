from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from tests.models import User, UserDecrypt, UserDisabledEncryption


class TestUnitEncryptionModel:
    """Test basic functionality of pydantic-encryption with mocked models."""

    def test_encrypt_field(self, user: User):
        """Test encrypting fields with Encrypt annotation."""

        assert user.username is not None
        assert getattr(user.address, "encrypted", False)

    def test_double_encrypt_fails(self, user: User):
        """Test double encrypting returns same value."""

        old_address = user.address

        user.address = FernetAdapter.encrypt(user.address)

        assert user.address == old_address

    def test_decrypt_field(self, user: User):
        """Test decrypting fields with Decrypt annotation."""

        encrypted_data = user.model_dump()

        decrypted_user = UserDecrypt(**encrypted_data)

        assert decrypted_user.username == user.username
        assert not getattr(decrypted_user.address, "encrypted", False)

    def test_disable_encryption(self, user_disabled: UserDisabledEncryption):
        """Test disabling encryption."""

        assert not getattr(user_disabled.address, "encrypted", False)

    def test_encrypt_multiple_users(self, users_batch: list[User]):
        """Test encrypting multiple users with batch."""

        for user in users_batch:
            assert getattr(user.address, "encrypted", False)
            assert user.username is not None
