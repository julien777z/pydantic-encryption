import pytest

from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyBlindIndex
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


@pytest.fixture(autouse=True)
def set_blind_index_key(monkeypatch):
    """Set a test blind index secret key for all tests."""

    from pydantic_encryption.integrations import sqlalchemy

    monkeypatch.setattr(sqlalchemy.settings, "BLIND_INDEX_SECRET_KEY", "test-secret-key-for-blind-index")


class TestSQLAlchemyBlindIndexHMAC:
    """Test SQLAlchemyBlindIndex with HMAC-SHA256 method."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyBlindIndex(BlindIndexMethod.HMAC_SHA256)

    def test_process_bind_param_none_returns_none(self):
        """Test that None input returns None."""

        result = self.type_adapter.process_bind_param(None, None)

        assert result is None

    def test_process_bind_param_string_returns_bytes(self):
        """Test that string input returns bytes."""

        result = self.type_adapter.process_bind_param("test@example.com", None)

        assert isinstance(result, bytes)
        assert len(result) == 32  # SHA-256 digest is 32 bytes

    def test_process_bind_param_bytes_returns_bytes(self):
        """Test that bytes input returns bytes."""

        result = self.type_adapter.process_bind_param(b"test@example.com", None)

        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_deterministic(self):
        """Test that same input always produces same output."""

        result1 = self.type_adapter.process_bind_param("test@example.com", None)
        result2 = self.type_adapter.process_bind_param("test@example.com", None)

        assert result1 == result2

    def test_process_bind_param_str_bytes_equivalent(self):
        """Test that string and equivalent bytes produce the same hash."""

        result_str = self.type_adapter.process_bind_param("hello", None)
        result_bytes = self.type_adapter.process_bind_param(b"hello", None)

        assert result_str == result_bytes

    def test_process_bind_param_different_inputs_differ(self):
        """Test that different inputs produce different hashes."""

        result1 = self.type_adapter.process_bind_param("user1@example.com", None)
        result2 = self.type_adapter.process_bind_param("user2@example.com", None)

        assert result1 != result2

    def test_process_literal_param_computes_hash(self):
        """Test that process_literal_param also computes the blind index."""

        bind_result = self.type_adapter.process_bind_param("test@example.com", None)
        literal_result = self.type_adapter.process_literal_param("test@example.com", None)

        assert bind_result == literal_result

    def test_process_literal_param_none_returns_none(self):
        """Test that None input returns None for literal param."""

        result = self.type_adapter.process_literal_param(None, None)

        assert result is None

    def test_process_result_value_none_returns_none(self):
        """Test that None result returns None."""

        result = self.type_adapter.process_result_value(None, None)

        assert result is None

    def test_process_result_value_returns_blind_index_value(self):
        """Test that result value is wrapped as BlindIndexValue."""

        test_bytes = b"\x01\x02\x03\x04" * 8

        result = self.type_adapter.process_result_value(test_bytes, None)

        assert isinstance(result, BlindIndexValue)
        assert result.blind_indexed is True
        assert result == test_bytes


class TestSQLAlchemyBlindIndexArgon2:
    """Test SQLAlchemyBlindIndex with Argon2 method."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyBlindIndex(BlindIndexMethod.ARGON2)

    def test_process_bind_param_none_returns_none(self):
        """Test that None input returns None."""

        result = self.type_adapter.process_bind_param(None, None)

        assert result is None

    def test_process_bind_param_string_returns_bytes(self):
        """Test that string input returns bytes."""

        result = self.type_adapter.process_bind_param("test@example.com", None)

        assert isinstance(result, bytes)
        assert len(result) == 32  # hash_len=32

    def test_process_bind_param_deterministic(self):
        """Test that same input always produces same output (fixed salt)."""

        result1 = self.type_adapter.process_bind_param("test@example.com", None)
        result2 = self.type_adapter.process_bind_param("test@example.com", None)

        assert result1 == result2

    def test_process_bind_param_different_inputs_differ(self):
        """Test that different inputs produce different hashes."""

        result1 = self.type_adapter.process_bind_param("user1@example.com", None)
        result2 = self.type_adapter.process_bind_param("user2@example.com", None)

        assert result1 != result2

    def test_process_bind_param_str_bytes_equivalent(self):
        """Test that string and equivalent bytes produce the same hash."""

        result_str = self.type_adapter.process_bind_param("hello", None)
        result_bytes = self.type_adapter.process_bind_param(b"hello", None)

        assert result_str == result_bytes


class TestSQLAlchemyBlindIndexConfig:
    """Test SQLAlchemyBlindIndex configuration and edge cases."""

    def test_missing_secret_key_raises_error(self, monkeypatch):
        """Test that missing BLIND_INDEX_SECRET_KEY raises ValueError."""

        from pydantic_encryption.integrations import sqlalchemy

        monkeypatch.setattr(sqlalchemy.settings, "BLIND_INDEX_SECRET_KEY", None)

        type_adapter = SQLAlchemyBlindIndex(BlindIndexMethod.HMAC_SHA256)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            type_adapter.process_bind_param("test", None)

    def test_different_keys_produce_different_indexes(self, monkeypatch):
        """Test that different secret keys produce different blind indexes."""

        from pydantic_encryption.integrations import sqlalchemy

        type_adapter = SQLAlchemyBlindIndex(BlindIndexMethod.HMAC_SHA256)

        monkeypatch.setattr(sqlalchemy.settings, "BLIND_INDEX_SECRET_KEY", "key-one")
        result1 = type_adapter.process_bind_param("test@example.com", None)

        monkeypatch.setattr(sqlalchemy.settings, "BLIND_INDEX_SECRET_KEY", "key-two")
        result2 = type_adapter.process_bind_param("test@example.com", None)

        assert result1 != result2

    def test_different_methods_produce_different_outputs(self):
        """Test that HMAC-SHA256 and Argon2 produce different outputs for same input."""

        hmac_adapter = SQLAlchemyBlindIndex(BlindIndexMethod.HMAC_SHA256)
        argon2_adapter = SQLAlchemyBlindIndex(BlindIndexMethod.ARGON2)

        hmac_result = hmac_adapter.process_bind_param("test@example.com", None)
        argon2_result = argon2_adapter.process_bind_param("test@example.com", None)

        assert hmac_result != argon2_result

    def test_default_method_is_hmac_sha256(self):
        """Test that the default method is HMAC-SHA256."""

        type_adapter = SQLAlchemyBlindIndex()

        assert type_adapter.method == BlindIndexMethod.HMAC_SHA256
