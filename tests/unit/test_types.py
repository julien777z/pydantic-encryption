import pytest

from pydantic_encryption.types import (
    DecryptedValue,
    EncryptedValue,
    HashedValue,
    NormalizeToBytes,
    NormalizeToString,
)


class TestNormalizeToBytes:
    """Test NormalizeToBytes type."""

    def test_from_string(self):
        """Test creating from string."""

        value = NormalizeToBytes("hello")

        assert isinstance(value, bytes)
        assert value == b"hello"

    def test_from_bytes(self):
        """Test creating from bytes."""

        value = NormalizeToBytes(b"hello")

        assert isinstance(value, bytes)
        assert value == b"hello"

    def test_unicode_string(self):
        """Test creating from unicode string."""

        value = NormalizeToBytes("日本語")

        assert isinstance(value, bytes)
        assert value == "日本語".encode("utf-8")


class TestNormalizeToString:
    """Test NormalizeToString type."""

    def test_from_bytes(self):
        """Test creating from bytes."""

        value = NormalizeToString(b"hello")

        assert isinstance(value, str)
        assert value == "hello"

    def test_from_string(self):
        """Test creating from string."""

        value = NormalizeToString("hello")

        assert isinstance(value, str)
        assert value == "hello"

    def test_unicode_bytes(self):
        """Test creating from unicode bytes."""

        value = NormalizeToString("日本語".encode("utf-8"))

        assert isinstance(value, str)
        assert value == "日本語"


class TestEncryptedValue:
    """Test EncryptedValue type."""

    def test_encrypted_flag(self):
        """Test encrypted flag is True."""

        value = EncryptedValue(b"encrypted")

        assert value.encrypted is True

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


class TestDecryptedValue:
    """Test DecryptedValue type."""

    def test_encrypted_flag(self):
        """Test encrypted flag is False."""
        value = DecryptedValue("decrypted")

        assert value.encrypted is False

    def test_from_bytes(self):
        """Test creating from bytes."""
        value = DecryptedValue(b"decrypted")

        assert isinstance(value, str)
        assert value == "decrypted"

    def test_from_string(self):
        """Test creating from string."""
        value = DecryptedValue("decrypted")

        assert isinstance(value, str)
        assert value == "decrypted"

    def test_is_str_subclass(self):
        """Test DecryptedValue is str subclass."""
        value = DecryptedValue("test")

        assert isinstance(value, str)


class TestHashedValue:
    """Test HashedValue type."""

    def test_hashed_flag(self):
        """Test hashed flag is True."""
        value = HashedValue(b"hashed")

        assert value.hashed is True

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
