import pytest

from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter
from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue

pytestmark = pytest.mark.asyncio


class TestFernetAdapter:
    """Test FernetAdapter encryption and decryption."""

    async def test_encrypt_string(self):
        """Test that encrypting a string returns an EncryptedValue."""

        plaintext = "secret data"
        encrypted = await FernetAdapter.encrypt(plaintext)

        assert isinstance(encrypted, EncryptedValue)
        assert encrypted != plaintext.encode("utf-8")

    async def test_encrypt_bytes(self):
        """Test that encrypting bytes returns an EncryptedValue."""

        encrypted = await FernetAdapter.encrypt(b"secret bytes")

        assert isinstance(encrypted, EncryptedValue)

    async def test_decrypt_returns_string(self):
        """Test that decrypting returns a plain string."""

        plaintext = "secret data"
        encrypted = await FernetAdapter.encrypt(plaintext)
        decrypted = await FernetAdapter.decrypt(encrypted)

        assert isinstance(decrypted, str)
        assert decrypted == plaintext

    async def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypt/decrypt roundtrip preserves data."""

        plaintext = "Hello, World! 🔐"
        encrypted = await FernetAdapter.encrypt(plaintext)
        decrypted = await FernetAdapter.decrypt(encrypted)

        assert decrypted == plaintext

    async def test_encrypt_already_encrypted_returns_same(self):
        """Test that encrypting an already-encrypted value returns the same value."""

        encrypted = await FernetAdapter.encrypt("secret")
        double_encrypted = await FernetAdapter.encrypt(encrypted)

        assert encrypted == double_encrypted

    async def test_encrypt_empty_string(self):
        """Test encrypting an empty string roundtrips cleanly."""

        encrypted = await FernetAdapter.encrypt("")
        decrypted = await FernetAdapter.decrypt(encrypted)

        assert decrypted == ""

    async def test_encrypt_special_characters(self):
        """Test encrypting special characters roundtrips cleanly."""

        plaintext = "!@#$%^&*()_+-={}[]|\\:\";<>?,./~`"
        encrypted = await FernetAdapter.encrypt(plaintext)
        decrypted = await FernetAdapter.decrypt(encrypted)

        assert decrypted == plaintext

    async def test_encrypt_unicode(self):
        """Test encrypting unicode characters roundtrips cleanly."""

        plaintext = "日本語 한국어 العربية 🎉🔒"
        encrypted = await FernetAdapter.encrypt(plaintext)
        decrypted = await FernetAdapter.decrypt(encrypted)

        assert decrypted == plaintext


class TestArgon2Adapter:
    """Test Argon2Adapter hashing."""

    async def test_hash_string(self):
        """Test that hashing a string returns a HashedValue."""

        value = "password123"
        hashed = await Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)
        assert hashed != value.encode("utf-8")

    async def test_hash_bytes(self):
        """Test that hashing bytes returns a HashedValue."""

        hashed = await Argon2Adapter.hash(b"password123")

        assert isinstance(hashed, HashedValue)

    async def test_hash_already_hashed_returns_same(self):
        """Test that hashing an already-hashed value returns the same value."""

        hashed = await Argon2Adapter.hash("password")
        double_hashed = await Argon2Adapter.hash(hashed)

        assert hashed == double_hashed

    async def test_hash_different_values_produce_different_hashes(self):
        """Test that different values produce different hashes."""

        hash1 = await Argon2Adapter.hash("password1")
        hash2 = await Argon2Adapter.hash("password2")

        assert hash1 != hash2

    async def test_hash_same_value_produces_different_hashes(self):
        """Test that the same value produces different hashes due to random salt."""

        hash1 = await Argon2Adapter.hash("password")
        hash2 = await Argon2Adapter.hash("password")

        assert hash1 != hash2

    async def test_hash_contains_argon2_prefix(self):
        """Test that hash output contains the Argon2 identifier."""

        hashed = await Argon2Adapter.hash("password")

        assert b"$argon2" in hashed

    async def test_hash_special_characters(self):
        """Test hashing special characters returns a HashedValue."""

        hashed = await Argon2Adapter.hash("!@#$%^&*()_+-={}[]|\\:\";<>?,./~`")

        assert isinstance(hashed, HashedValue)

    async def test_hash_unicode(self):
        """Test hashing unicode characters returns a HashedValue."""

        hashed = await Argon2Adapter.hash("日本語パスワード🔒")

        assert isinstance(hashed, HashedValue)


class TestHMACSHA256Adapter:
    """Test HMACSHA256Adapter blind indexing."""

    TEST_KEY = b"test-secret-key"

    async def test_compute_blind_index_string(self):
        """Test that compute_blind_index on a string returns a BlindIndexValue of 32 bytes."""

        result = await HMACSHA256Adapter.compute_blind_index("test@example.com", self.TEST_KEY)

        assert isinstance(result, BlindIndexValue)
        assert len(result) == 32

    async def test_compute_blind_index_bytes(self):
        """Test that compute_blind_index on bytes returns a BlindIndexValue."""

        result = await HMACSHA256Adapter.compute_blind_index(b"test@example.com", self.TEST_KEY)

        assert isinstance(result, BlindIndexValue)

    async def test_compute_blind_index_deterministic(self):
        """Test that compute_blind_index returns the same digest for the same input."""

        result1 = await HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        result2 = await HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)

        assert result1 == result2

    async def test_compute_blind_index_already_indexed_returns_same(self):
        """Test that passing an already-indexed value returns it unchanged."""

        result = await HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        double_indexed = await HMACSHA256Adapter.compute_blind_index(result, self.TEST_KEY)

        assert result == double_indexed


class TestArgon2BlindIndexAdapter:
    """Test Argon2BlindIndexAdapter blind indexing."""

    TEST_KEY = b"test-secret-key"

    async def test_compute_blind_index_already_indexed_returns_same(self):
        """Test that passing an already-indexed value returns it unchanged."""

        result = await Argon2BlindIndexAdapter.compute_blind_index("test", self.TEST_KEY)
        double_indexed = await Argon2BlindIndexAdapter.compute_blind_index(result, self.TEST_KEY)

        assert result == double_indexed
