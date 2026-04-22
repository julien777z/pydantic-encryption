import pytest

from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import HashedValue
from tests.models import User

pytestmark = pytest.mark.asyncio


class TestUnitHashing:
    """Test basic functionality of pydantic-encryption hashing."""

    async def test_hash_field(self, user: User):
        """Test hashing fields with Hashed annotation."""

        assert user.username is not None
        assert isinstance(user.password, HashedValue)

    async def test_double_hash_fails(self, user: User):
        """Test that hashing an already-hashed value returns it unchanged."""

        old_password = user.password
        user.password = await Argon2Adapter.hash(user.password)

        assert user.password == old_password

    async def test_hash_multiple_users(self, users_batch: list[User]):
        """Test hashing multiple users produced by the batch factory fixture."""

        for user in users_batch:
            assert isinstance(user.password, HashedValue)
