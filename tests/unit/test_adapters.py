import pytest

from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue


class TestFernetAdapter:
    """Test FernetAdapter encryption and decryption."""

    def test_encrypt_string(self):
        """Test encrypting a string."""
        plaintext = "secret data"
        encrypted = FernetAdapter.encrypt(plaintext)

        assert isinstance(encrypted, EncryptedValue)
        assert isinstance(encrypted, EncryptedValue)
        assert encrypted != plaintext.encode("utf-8")

    def test_encrypt_bytes(self):
        """Test encrypting bytes."""
        plaintext = b"secret bytes"
        encrypted = FernetAdapter.encrypt(plaintext)

        assert isinstance(encrypted, EncryptedValue)
        assert isinstance(encrypted, EncryptedValue)

    def test_decrypt_returns_string(self):
        """Test decrypting returns plain string."""
        plaintext = "secret data"
        encrypted = FernetAdapter.encrypt(plaintext)
        decrypted = FernetAdapter.decrypt(encrypted)

        assert isinstance(decrypted, str)
        assert decrypted == plaintext

    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt/decrypt roundtrip preserves data."""
        plaintext = "Hello, World! 🔐"
        encrypted = FernetAdapter.encrypt(plaintext)
        decrypted = FernetAdapter.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_already_encrypted_returns_same(self):
        """Test encrypting already encrypted value returns same value."""
        plaintext = "secret"
        encrypted = FernetAdapter.encrypt(plaintext)
        double_encrypted = FernetAdapter.encrypt(encrypted)

        assert encrypted == double_encrypted

    def test_encrypt_empty_string(self):
        """Test encrypting empty string."""
        encrypted = FernetAdapter.encrypt("")
        decrypted = FernetAdapter.decrypt(encrypted)

        assert decrypted == ""

    def test_encrypt_special_characters(self):
        """Test encrypting special characters."""
        plaintext = "!@#$%^&*()_+-={}[]|\\:\";<>?,./~`"
        encrypted = FernetAdapter.encrypt(plaintext)
        decrypted = FernetAdapter.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encrypt_unicode(self):
        """Test encrypting unicode characters."""
        plaintext = "日本語 한국어 العربية 🎉🔒"
        encrypted = FernetAdapter.encrypt(plaintext)
        decrypted = FernetAdapter.decrypt(encrypted)

        assert decrypted == plaintext


class TestArgon2Adapter:
    """Test Argon2Adapter hashing."""

    def test_hash_string(self):
        """Test hashing a string."""
        value = "password123"
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)
        assert hashed != value.encode("utf-8")

    def test_hash_bytes(self):
        """Test hashing bytes."""
        value = b"password123"
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)

    def test_hash_already_hashed_returns_same(self):
        """Test hashing already hashed value returns same value."""
        value = "password"
        hashed = Argon2Adapter.hash(value)
        double_hashed = Argon2Adapter.hash(hashed)

        assert hashed == double_hashed

    def test_hash_different_values_produce_different_hashes(self):
        """Test different values produce different hashes."""
        hash1 = Argon2Adapter.hash("password1")
        hash2 = Argon2Adapter.hash("password2")

        assert hash1 != hash2

    def test_hash_same_value_produces_different_hashes(self):
        """Test same value produces different hashes (due to salt)."""
        hash1 = Argon2Adapter.hash("password")
        hash2 = Argon2Adapter.hash("password")

        assert hash1 != hash2

    def test_hash_contains_argon2_prefix(self):
        """Test hash output contains argon2 identifier."""
        hashed = Argon2Adapter.hash("password")

        assert b"$argon2" in hashed

    def test_hash_special_characters(self):
        """Test hashing special characters."""
        value = "!@#$%^&*()_+-={}[]|\\:\";<>?,./~`"
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)

    def test_hash_unicode(self):
        """Test hashing unicode characters."""
        value = "日本語パスワード🔒"
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)


class TestHMACSHA256Adapter:
    """Test HMACSHA256Adapter blind indexing."""

    TEST_KEY = b"test-secret-key"

    def test_compute_blind_index_string(self):
        result = HMACSHA256Adapter.compute_blind_index("test@example.com", self.TEST_KEY)
        assert isinstance(result, BlindIndexValue)
        assert isinstance(result, BlindIndexValue)
        assert len(result) == 32

    def test_compute_blind_index_bytes(self):
        result = HMACSHA256Adapter.compute_blind_index(b"test@example.com", self.TEST_KEY)
        assert isinstance(result, BlindIndexValue)

    def test_compute_blind_index_deterministic(self):
        result1 = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        result2 = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        assert result1 == result2

    def test_compute_blind_index_already_indexed_returns_same(self):
        result = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        double_indexed = HMACSHA256Adapter.compute_blind_index(result, self.TEST_KEY)
        assert result == double_indexed


class TestArgon2BlindIndexAdapter:
    """Test Argon2BlindIndexAdapter blind indexing."""

    TEST_KEY = b"test-secret-key"

    def test_compute_blind_index_already_indexed_returns_same(self):
        from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter

        result = Argon2BlindIndexAdapter.compute_blind_index("test", self.TEST_KEY)
        double_indexed = Argon2BlindIndexAdapter.compute_blind_index(result, self.TEST_KEY)
        assert result == double_indexed


