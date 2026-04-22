import pytest

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.types import EncryptedValue
from tests.models import User

pytestmark = pytest.mark.asyncio


class TestUnitEncryptionModel:
    """Test basic functionality of pydantic-encryption with mocked models."""

    async def test_encrypt_field(self, user: User):
        """Test encrypting fields with Encrypted annotation."""

        assert user.username is not None
        assert isinstance(user.address, EncryptedValue)

    async def test_double_encrypt_fails(self, user: User):
        """Test that encrypting an already-encrypted value returns it unchanged."""

        old_address = user.address
        user.address = await FernetAdapter.encrypt(user.address)

        assert user.address == old_address

    async def test_decrypt_field(self, user: User):
        """Test decrypting fields with decrypt_data()."""

        original_username = user.username
        await user.decrypt_data()

        assert user.username == original_username
        assert not isinstance(user.address, EncryptedValue)

    async def test_encrypt_multiple_users(self, users_batch: list[User]):
        """Test encrypting multiple users produced by the batch factory fixture."""

        for user in users_batch:
            assert isinstance(user.address, EncryptedValue)
            assert user.username is not None
