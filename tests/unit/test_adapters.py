import pytest
from cryptography.fernet import InvalidToken

from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import (
    FERNET_CLIENT_CACHE_SIZE,
    FernetAdapter,
    build_fernet_client,
    derive_context_key,
)
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import BlindIndexValue, EncryptedValue, HashedValue


class TestFernetAdapter:
    """Test FernetAdapter encryption and decryption under a bound context."""

    CONTEXT = b"tests.adapters.first_column"
    OTHER_CONTEXT = b"tests.adapters.second_column"

    @pytest.mark.parametrize(
        "plaintext",
        [
            "",
            "secret data",
            "Hello, World! 🔐",
            "日本語 한국어 العربية 🎉🔒",
            '!@#$%^&*()_+-={}[]|\\:";<>?,./~`',
        ],
        ids=["empty", "ascii", "mixed", "unicode", "punctuation"],
    )
    def test_round_trip_under_the_matching_context(self, fernet_key: str, plaintext: str):
        """Test that decrypt returns the plaintext when handed the context encrypt was given."""

        encrypted = FernetAdapter.encrypt(plaintext, key=fernet_key, associated_data=self.CONTEXT)

        assert isinstance(encrypted, EncryptedValue)
        assert encrypted != plaintext.encode("utf-8")
        assert FernetAdapter.decrypt(encrypted, key=fernet_key, associated_data=self.CONTEXT) == plaintext

    def test_encrypt_bytes(self, fernet_key: str):
        """Test that bytes plaintext seals the same way a str does."""

        encrypted = FernetAdapter.encrypt(b"secret bytes", key=fernet_key, associated_data=self.CONTEXT)

        assert isinstance(encrypted, EncryptedValue)

    def test_decrypt_under_a_different_context_fails(self, fernet_key: str):
        """Test that a value lifted into another context fails to open there."""

        encrypted = FernetAdapter.encrypt("secret data", key=fernet_key, associated_data=self.CONTEXT)

        with pytest.raises(InvalidToken):
            FernetAdapter.decrypt(encrypted, key=fernet_key, associated_data=self.OTHER_CONTEXT)

    def test_each_context_derives_its_own_key(self, fernet_key: str):
        """Test that two contexts under one root key seal under different derived keys."""

        first = derive_context_key(fernet_key, self.CONTEXT)
        second = derive_context_key(fernet_key, self.OTHER_CONTEXT)

        assert first != second
        assert first == derive_context_key(fernet_key, self.CONTEXT)

    def test_encrypt_already_encrypted_returns_same(self, fernet_key: str):
        """Test that encrypting an already encrypted value returns it unchanged."""

        encrypted = FernetAdapter.encrypt("secret", key=fernet_key, associated_data=self.CONTEXT)
        double_encrypted = FernetAdapter.encrypt(encrypted, key=fernet_key, associated_data=self.CONTEXT)

        assert encrypted == double_encrypted

    def test_encrypt_raises_without_a_root_key(self, monkeypatch: pytest.MonkeyPatch):
        """Test that encrypt raises when neither an explicit key nor ENCRYPTION_KEY is set."""

        monkeypatch.setattr(settings, "ENCRYPTION_KEY", None)

        with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
            FernetAdapter.encrypt("secret data", associated_data=self.CONTEXT)


class TestFernetClientCache:
    """Test that the per-context Fernet clients are kept to a bounded set."""

    CONTEXT = b"tests.adapters.cache"

    def test_repeated_context_reuses_one_client(self, fernet_key: str):
        """Test that a context already held is served without building a second client."""

        first = FernetAdapter.get_client(fernet_key, self.CONTEXT)
        second = FernetAdapter.get_client(fernet_key, self.CONTEXT)

        assert first is second

    def test_cache_never_grows_past_its_bound(self, fernet_key: str):
        """Test that a stream of one-off contexts cannot grow the cache without limit."""

        build_fernet_client.cache_clear()

        for row in range(FERNET_CLIENT_CACHE_SIZE + 100):
            FernetAdapter.get_client(fernet_key, f"users.secret.{row}".encode("utf-8"))

        assert build_fernet_client.cache_info().currsize == FERNET_CLIENT_CACHE_SIZE

    def test_evicted_context_still_opens_its_own_ciphertext(self, fernet_key: str):
        """Test that a context evicted from the cache decrypts what it sealed after rebuilding."""

        encrypted = FernetAdapter.encrypt("secret data", key=fernet_key, associated_data=self.CONTEXT)
        build_fernet_client.cache_clear()

        assert FernetAdapter.decrypt(encrypted, key=fernet_key, associated_data=self.CONTEXT) == "secret data"


class TestArgon2Adapter:
    """Test Argon2Adapter hashing."""

    def test_hash_string(self):
        """Test hashing a string."""
        value = "password123"
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)
        assert hashed != value.encode("utf-8")

    def test_hash_bytes(self):
        """Test hashing bytes."""
        value = b"password123"
        hashed = Argon2Adapter.hash(value)

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
        value = '!@#$%^&*()_+-={}[]|\\:";<>?,./~`'
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)

    def test_hash_unicode(self):
        """Test hashing unicode characters."""
        value = "日本語パスワード🔒"
        hashed = Argon2Adapter.hash(value)

        assert isinstance(hashed, HashedValue)


class TestHMACSHA256Adapter:
    """Test HMACSHA256Adapter blind indexing."""

    TEST_KEY = b"test-secret-key"

    def test_compute_blind_index_string(self):
        result = HMACSHA256Adapter.compute_blind_index("test@example.com", self.TEST_KEY)
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

    def test_compute_blind_index_salt_changes_output(self):
        unsalted = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        salted = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY, salt=b"salt-bytes")
        assert salted != unsalted

    def test_compute_blind_index_salt_none_matches_default(self):
        explicit_none = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY, salt=None)
        default = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY)
        assert explicit_none == default

    def test_compute_blind_index_salted_deterministic(self):
        first = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY, salt=b"salt-bytes")
        second = HMACSHA256Adapter.compute_blind_index("test", self.TEST_KEY, salt=b"salt-bytes")
        assert first == second


class TestArgon2BlindIndexAdapter:
    """Test Argon2BlindIndexAdapter blind indexing."""

    TEST_KEY = b"test-secret-key"

    def test_compute_blind_index_already_indexed_returns_same(self):
        from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter

        result = Argon2BlindIndexAdapter.compute_blind_index("test", self.TEST_KEY)
        double_indexed = Argon2BlindIndexAdapter.compute_blind_index(result, self.TEST_KEY)
        assert result == double_indexed
