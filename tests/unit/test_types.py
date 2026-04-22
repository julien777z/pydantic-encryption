from pydantic_encryption.types import (
    EncryptedValue,
    HashedValue,
)


class TestEncryptedValue:
    """Test EncryptedValue type."""

    def test_is_encrypted_value_instance(self):
        """Test that the constructor returns an EncryptedValue instance."""

        value = EncryptedValue(b"encrypted")

        assert isinstance(value, EncryptedValue)

    def test_from_string(self):
        """Test creating from string."""

        value = EncryptedValue("encrypted")

        assert isinstance(value, bytes)
        assert value == b"encrypted"

    def test_from_bytes(self):
        """Test creating from bytes."""

        value = EncryptedValue(b"encrypted")

        assert isinstance(value, bytes)
        assert value == b"encrypted"

    def test_is_bytes_subclass(self):
        """Test EncryptedValue is bytes subclass."""

        value = EncryptedValue(b"test")

        assert isinstance(value, bytes)


class TestHashedValue:
    """Test HashedValue type."""

    def test_is_hashed_value_instance(self):
        """Test that the constructor returns a HashedValue instance."""

        value = HashedValue(b"hashed")

        assert isinstance(value, HashedValue)

    def test_from_string(self):
        """Test creating from string."""
        value = HashedValue("hashed")

        assert isinstance(value, bytes)
        assert value == b"hashed"

    def test_from_bytes(self):
        """Test creating from bytes."""
        value = HashedValue(b"hashed")

        assert isinstance(value, bytes)
        assert value == b"hashed"

    def test_is_bytes_subclass(self):
        """Test HashedValue is bytes subclass."""
        value = HashedValue(b"test")

        assert isinstance(value, bytes)
