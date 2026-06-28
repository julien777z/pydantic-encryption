import hashlib
import hmac

import pytest

from pydantic_encryption import make_blind_index
from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue

TEST_KEY = "unit-make-blind-index-key"
ORG_SALT = b"\x11" * 16
OTHER_SALT = b"\x22" * 16


class TestMakeBlindIndexHMAC:
    """Test make_blind_index with HMAC-SHA256."""

    def test_returns_blind_index_value(self):
        """Test that the factory returns a 32-byte BlindIndexValue."""

        result = make_blind_index("test@example.com", method=BlindIndexMethod.HMAC_SHA256, key=TEST_KEY)

        assert isinstance(result, BlindIndexValue)
        assert len(result) == 32

    def test_unsalted_matches_adapter(self):
        """Test that salt=None reproduces the bare adapter output (backward compatible)."""

        expected = HMACSHA256Adapter.compute_blind_index("test@example.com", TEST_KEY.encode("utf-8"))
        result = make_blind_index("test@example.com", method=BlindIndexMethod.HMAC_SHA256, key=TEST_KEY)

        assert result == expected

    def test_unsalted_matches_manual_hmac(self):
        """Test that salt=None equals a plain HMAC-SHA256 over the value with no salt folded in."""

        expected = hmac.new(TEST_KEY.encode("utf-8"), b"test@example.com", hashlib.sha256).digest()
        result = make_blind_index("test@example.com", method=BlindIndexMethod.HMAC_SHA256, key=TEST_KEY)

        assert bytes(result) == expected

    def test_salted_differs_from_unsalted(self):
        """Test that providing a salt changes the output."""

        unsalted = make_blind_index("5550100", method=BlindIndexMethod.HMAC_SHA256, key=TEST_KEY)
        salted = make_blind_index(
            "5550100", method=BlindIndexMethod.HMAC_SHA256, salt=ORG_SALT, key=TEST_KEY
        )

        assert salted != unsalted

    def test_same_value_and_salt_reproduce(self):
        """Test that the same (value, salt) pair is deterministic."""

        first = make_blind_index("5550100", method=BlindIndexMethod.HMAC_SHA256, salt=ORG_SALT, key=TEST_KEY)
        second = make_blind_index("5550100", method=BlindIndexMethod.HMAC_SHA256, salt=ORG_SALT, key=TEST_KEY)

        assert first == second

    def test_different_salts_differ(self):
        """Test that the same value under different salts yields different indices."""

        first = make_blind_index("5550100", method=BlindIndexMethod.HMAC_SHA256, salt=ORG_SALT, key=TEST_KEY)
        second = make_blind_index(
            "5550100", method=BlindIndexMethod.HMAC_SHA256, salt=OTHER_SALT, key=TEST_KEY
        )

        assert first != second

    def test_normalization_applied_before_salting(self):
        """Test that normalization runs before the salt is folded in."""

        formatted = make_blind_index(
            "555-0100",
            method=BlindIndexMethod.HMAC_SHA256,
            salt=ORG_SALT,
            strip_non_digits=True,
            key=TEST_KEY,
        )
        digits = make_blind_index(
            "5550100",
            method=BlindIndexMethod.HMAC_SHA256,
            salt=ORG_SALT,
            strip_non_digits=True,
            key=TEST_KEY,
        )

        assert formatted == digits

    def test_salt_uses_length_prefixed_encoding(self):
        """Test that the salted HMAC folds in a length-tagged salt before the normalized value."""

        message = len(ORG_SALT).to_bytes(4, "big") + ORG_SALT + b"5550100"
        expected = hmac.new(TEST_KEY.encode("utf-8"), message, hashlib.sha256).digest()
        result = make_blind_index(
            "555-0100",
            method=BlindIndexMethod.HMAC_SHA256,
            salt=ORG_SALT,
            strip_non_digits=True,
            key=TEST_KEY,
        )

        assert bytes(result) == expected

    def test_variable_length_salts_do_not_collide(self):
        """Test that different (salt, value) pairs with the same naive concatenation stay distinct."""

        first = make_blind_index("34", method=BlindIndexMethod.HMAC_SHA256, salt=b"1", key=TEST_KEY)
        second = make_blind_index("4", method=BlindIndexMethod.HMAC_SHA256, salt=b"13", key=TEST_KEY)

        assert first != second

    def test_resolves_key_from_settings(self, monkeypatch):
        """Test that the key defaults to BLIND_INDEX_SECRET_KEY when not passed."""

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", TEST_KEY)

        from_settings = make_blind_index("test@example.com", method=BlindIndexMethod.HMAC_SHA256)
        explicit = make_blind_index("test@example.com", method=BlindIndexMethod.HMAC_SHA256, key=TEST_KEY)

        assert from_settings == explicit

    def test_missing_key_raises(self, monkeypatch):
        """Test that a missing secret key raises a clear error."""

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            make_blind_index("test@example.com", method=BlindIndexMethod.HMAC_SHA256)

    def test_blind_index_value_passes_through(self):
        """Test that an already-computed BlindIndexValue is returned unchanged."""

        precomputed = make_blind_index(
            "5550100", method=BlindIndexMethod.HMAC_SHA256, salt=ORG_SALT, key=TEST_KEY
        )
        again = make_blind_index(
            precomputed, method=BlindIndexMethod.HMAC_SHA256, salt=OTHER_SALT, key=TEST_KEY
        )

        assert again == precomputed


class TestMakeBlindIndexArgon2:
    """Test make_blind_index with Argon2."""

    def test_unsalted_deterministic(self):
        """Test that Argon2 indices are deterministic with no salt."""

        first = make_blind_index("test", method=BlindIndexMethod.ARGON2, key=TEST_KEY)
        second = make_blind_index("test", method=BlindIndexMethod.ARGON2, key=TEST_KEY)

        assert first == second
        assert len(first) == 32

    def test_salted_differs_from_unsalted(self):
        """Test that an Argon2 salt changes the output."""

        unsalted = make_blind_index("test", method=BlindIndexMethod.ARGON2, key=TEST_KEY)
        salted = make_blind_index("test", method=BlindIndexMethod.ARGON2, salt=ORG_SALT, key=TEST_KEY)

        assert salted != unsalted
