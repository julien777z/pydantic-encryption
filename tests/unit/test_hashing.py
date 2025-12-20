from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from tests.models import User, UserDisabledEncryption


class TestUnitHashing:
    """Test basic functionality of pydantic-encryption hashing."""

    def test_hash_field(self, user: User):
        """Test hashing fields with Hash annotation."""
        assert user.username is not None
        assert getattr(user.password, "hashed", False)

    def test_double_hash_fails(self, user: User):
        """Test double hashing returns same value."""
        old_password = user.password

        user.password = Argon2Adapter.hash(user.password)

        assert user.password == old_password

    def test_disable_hashing(self, user_disabled: UserDisabledEncryption):
        """Test disabling hashing."""
        assert not getattr(user_disabled.password, "hashed", False)

    def test_hash_multiple_users(self, users_batch: list[User]):
        """Test hashing multiple users with batch."""
        for user in users_batch:
            assert getattr(user.password, "hashed", False)
