import pytest

from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue


class TestAsyncFernetAdapter:
    """Test FernetAdapter async encryption and decryption."""

    @pytest.mark.asyncio
    async def test_async_encrypt_string(self):
        plaintext = "secret data"
        encrypted = await FernetAdapter.async_encrypt(plaintext)

        assert isinstance(encrypted, EncryptedValue)
        assert isinstance(encrypted, EncryptedValue)
        assert encrypted != plaintext.encode("utf-8")

    @pytest.mark.asyncio
    async def test_async_encrypt_bytes(self):
        plaintext = b"secret bytes"
        encrypted = await FernetAdapter.async_encrypt(plaintext)

        assert isinstance(encrypted, EncryptedValue)
        assert isinstance(encrypted, EncryptedValue)

    @pytest.mark.asyncio
    async def test_async_decrypt_returns_string(self):
        plaintext = "secret data"
        encrypted = await FernetAdapter.async_encrypt(plaintext)
        decrypted = await FernetAdapter.async_decrypt(encrypted)

        assert isinstance(decrypted, str)
        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_async_encrypt_decrypt_roundtrip(self):
        plaintext = "Hello, World! 🔐"
        encrypted = await FernetAdapter.async_encrypt(plaintext)
        decrypted = await FernetAdapter.async_decrypt(encrypted)

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_async_encrypt_already_encrypted_returns_same(self):
        plaintext = "secret"
        encrypted = await FernetAdapter.async_encrypt(plaintext)
        double_encrypted = await FernetAdapter.async_encrypt(encrypted)

        assert encrypted == double_encrypted

    @pytest.mark.asyncio
    async def test_async_encrypt_empty_string(self):
        encrypted = await FernetAdapter.async_encrypt("")
        decrypted = await FernetAdapter.async_decrypt(encrypted)

        assert decrypted == ""

    @pytest.mark.asyncio
    async def test_async_encrypt_special_characters(self):
        plaintext = "!@#$%^&*()_+-={}[]|\\:\";<>?,./~`"
        encrypted = await FernetAdapter.async_encrypt(plaintext)
        decrypted = await FernetAdapter.async_decrypt(encrypted)

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_async_encrypt_unicode(self):
        plaintext = "日本語 한국어 العربية 🎉🔒"
        encrypted = await FernetAdapter.async_encrypt(plaintext)
        decrypted = await FernetAdapter.async_decrypt(encrypted)

        assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_async_matches_sync(self):
        """Async encrypt produces ciphertext that sync decrypt can read, and vice versa."""
        plaintext = "cross-compat test"

        encrypted_async = await FernetAdapter.async_encrypt(plaintext)
        decrypted_sync = FernetAdapter.decrypt(encrypted_async)
        assert decrypted_sync == plaintext

        encrypted_sync = FernetAdapter.encrypt(plaintext)
        decrypted_async = await FernetAdapter.async_decrypt(encrypted_sync)
        assert decrypted_async == plaintext


class TestAsyncArgon2Adapter:
    """Test Argon2Adapter async hashing."""

    @pytest.mark.asyncio
    async def test_async_hash_string(self):
        value = "password123"
        hashed = await Argon2Adapter.async_hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)
        assert hashed != value.encode("utf-8")

    @pytest.mark.asyncio
    async def test_async_hash_bytes(self):
        value = b"password123"
        hashed = await Argon2Adapter.async_hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)

    @pytest.mark.asyncio
    async def test_async_hash_already_hashed_returns_same(self):
        value = "password"
        hashed = await Argon2Adapter.async_hash(value)
        double_hashed = await Argon2Adapter.async_hash(hashed)

        assert hashed == double_hashed

    @pytest.mark.asyncio
    async def test_async_hash_different_values_produce_different_hashes(self):
        hash1 = await Argon2Adapter.async_hash("password1")
        hash2 = await Argon2Adapter.async_hash("password2")

        assert hash1 != hash2

    @pytest.mark.asyncio
    async def test_async_hash_contains_argon2_prefix(self):
        hashed = await Argon2Adapter.async_hash("password")

        assert b"$argon2" in hashed

    @pytest.mark.asyncio
    async def test_async_hash_unicode(self):
        value = "日本語パスワード🔒"
        hashed = await Argon2Adapter.async_hash(value)

        assert isinstance(hashed, HashedValue)
        assert isinstance(hashed, HashedValue)


class TestAsyncHMACSHA256Adapter:
    """Test HMACSHA256Adapter async blind indexing."""

    TEST_KEY = b"test-secret-key"

    @pytest.mark.asyncio
    async def test_async_compute_blind_index_string(self):
        result = await HMACSHA256Adapter.async_compute_blind_index("test@example.com", self.TEST_KEY)
        assert isinstance(result, BlindIndexValue)
        assert isinstance(result, BlindIndexValue)
        assert len(result) == 32

    @pytest.mark.asyncio
    async def test_async_compute_blind_index_bytes(self):
        result = await HMACSHA256Adapter.async_compute_blind_index(b"test@example.com", self.TEST_KEY)
        assert isinstance(result, BlindIndexValue)

    @pytest.mark.asyncio
    async def test_async_compute_blind_index_deterministic(self):
        result1 = await HMACSHA256Adapter.async_compute_blind_index("test", self.TEST_KEY)
        result2 = await HMACSHA256Adapter.async_compute_blind_index("test", self.TEST_KEY)
        assert result1 == result2

    @pytest.mark.asyncio
    async def test_async_compute_blind_index_already_indexed_returns_same(self):
        result = await HMACSHA256Adapter.async_compute_blind_index("test", self.TEST_KEY)
        double_indexed = await HMACSHA256Adapter.async_compute_blind_index(result, self.TEST_KEY)
        assert result == double_indexed

    @pytest.mark.asyncio
    async def test_async_matches_sync(self):
        """Async and sync produce identical blind indexes."""
        sync_result = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        async_result = await HMACSHA256Adapter.async_compute_blind_index("test", self.TEST_KEY)
        assert sync_result == async_result


class TestAsyncArgon2BlindIndexAdapter:
    """Test Argon2BlindIndexAdapter async blind indexing."""

    TEST_KEY = b"test-secret-key"

    @pytest.mark.asyncio
    async def test_async_compute_blind_index_already_indexed_returns_same(self):
        from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter

        result = await Argon2BlindIndexAdapter.async_compute_blind_index("test", self.TEST_KEY)
        double_indexed = await Argon2BlindIndexAdapter.async_compute_blind_index(result, self.TEST_KEY)
        assert result == double_indexed

    @pytest.mark.asyncio
    async def test_async_matches_sync(self):
        """Async and sync produce identical blind indexes."""
        from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter

        sync_result = Argon2BlindIndexAdapter.compute_blind_index("test", self.TEST_KEY)
        async_result = await Argon2BlindIndexAdapter.async_compute_blind_index("test", self.TEST_KEY)
        assert sync_result == async_result
