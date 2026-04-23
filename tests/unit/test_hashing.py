from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import HashedValue
from tests.factories import User


class TestUnitHashing:
    """Test basic functionality of pydantic-encryption hashing."""

    def test_hash_field(self, user: User):
        """Test hashing fields with Hash annotation."""
        assert user.username is not None
        assert isinstance(user.password, HashedValue)

    def test_double_hash_fails(self, user: User):
        """Test double hashing returns same value."""
        old_password = user.password

        user.password = Argon2Adapter.hash(user.password)

        assert user.password == old_password

    def test_hash_multiple_users(self, users_batch: list[User]):
        """Test hashing multiple users with batch."""
        for user in users_batch:
            assert isinstance(user.password, HashedValue)
