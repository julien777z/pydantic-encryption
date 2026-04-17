from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from tests.models import User


class TestUnitEncryptionModel:
    """Test basic functionality of pydantic-encryption with mocked models."""

    def test_encrypt_field(self, user: User):
        """Test encrypting fields with Encrypted annotation."""

        assert user.username is not None
        assert getattr(user.address, "encrypted", False)

    def test_double_encrypt_fails(self, user: User):
        """Test double encrypting returns same value."""

        old_address = user.address

        user.address = FernetAdapter.encrypt(user.address)

        assert user.address == old_address

    def test_decrypt_field(self, user: User):
        """Test decrypting fields with decrypt_fields()."""

        original_username = user.username
        user.decrypt_fields()

        assert user.username == original_username
        assert not getattr(user.address, "encrypted", False)

    def test_encrypt_multiple_users(self, users_batch: list[User]):
        """Test encrypting multiple users with batch."""

        for user in users_batch:
            assert getattr(user.address, "encrypted", False)
            assert user.username is not None
