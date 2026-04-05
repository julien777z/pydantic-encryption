import pytest

from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


@pytest.fixture(autouse=True)
def set_blind_index_key(monkeypatch):
    """Set a test blind index secret key for all tests."""

    from pydantic_encryption.integrations.sqlalchemy import blind_index as blind_index_module

    monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", "test-secret-key-for-blind-index")


class TestSQLAlchemyBlindIndexValueHMAC:
    """Test SQLAlchemyBlindIndexValue with HMAC-SHA256 method."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

    def test_process_bind_param_none_returns_none(self):
        assert self.type_adapter.process_bind_param(None, None) is None

    def test_process_bind_param_string_returns_bytes(self):
        result = self.type_adapter.process_bind_param("test@example.com", None)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_bytes_returns_bytes(self):
        result = self.type_adapter.process_bind_param(b"test@example.com", None)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_deterministic(self):
        result1 = self.type_adapter.process_bind_param("test@example.com", None)
        result2 = self.type_adapter.process_bind_param("test@example.com", None)
        assert result1 == result2

    def test_process_bind_param_str_bytes_equivalent(self):
        result_str = self.type_adapter.process_bind_param("hello", None)
        result_bytes = self.type_adapter.process_bind_param(b"hello", None)
        assert result_str == result_bytes

    def test_process_bind_param_different_inputs_differ(self):
        result1 = self.type_adapter.process_bind_param("user1@example.com", None)
        result2 = self.type_adapter.process_bind_param("user2@example.com", None)
        assert result1 != result2

    def test_process_literal_param_computes_hash(self):
        bind_result = self.type_adapter.process_bind_param("test@example.com", None)
        literal_result = self.type_adapter.process_literal_param("test@example.com", None)
        assert bind_result == literal_result

    def test_process_bind_param_already_indexed_returns_same(self):
        result = self.type_adapter.process_bind_param("test@example.com", None)
        blind_index_value = BlindIndexValue(result)
        double_indexed = self.type_adapter.process_bind_param(blind_index_value, None)
        assert result == double_indexed

    def test_process_literal_param_already_indexed_returns_same(self):
        result = self.type_adapter.process_literal_param("test@example.com", None)
        blind_index_value = BlindIndexValue(result)
        double_indexed = self.type_adapter.process_literal_param(blind_index_value, None)
        assert result == double_indexed

    def test_process_literal_param_none_returns_none(self):
        assert self.type_adapter.process_literal_param(None, None) is None

    def test_process_result_value_none_returns_none(self):
        assert self.type_adapter.process_result_value(None, None) is None

    def test_process_result_value_returns_blind_index_value(self):
        test_bytes = b"\x01\x02\x03\x04" * 8
        result = self.type_adapter.process_result_value(test_bytes, None)
        assert isinstance(result, BlindIndexValue)
        assert result.blind_indexed is True
        assert result == test_bytes


class TestSQLAlchemyBlindIndexValueArgon2:
    """Test SQLAlchemyBlindIndexValue with Argon2 method."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2)

    def test_process_bind_param_none_returns_none(self):
        assert self.type_adapter.process_bind_param(None, None) is None

    def test_process_bind_param_string_returns_bytes(self):
        result = self.type_adapter.process_bind_param("test@example.com", None)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_deterministic(self):
        result1 = self.type_adapter.process_bind_param("test@example.com", None)
        result2 = self.type_adapter.process_bind_param("test@example.com", None)
        assert result1 == result2

    def test_process_bind_param_different_inputs_differ(self):
        result1 = self.type_adapter.process_bind_param("user1@example.com", None)
        result2 = self.type_adapter.process_bind_param("user2@example.com", None)
        assert result1 != result2

    def test_process_bind_param_str_bytes_equivalent(self):
        result_str = self.type_adapter.process_bind_param("hello", None)
        result_bytes = self.type_adapter.process_bind_param(b"hello", None)
        assert result_str == result_bytes


class TestSQLAlchemyBlindIndexValueConfig:
    """Test SQLAlchemyBlindIndexValue configuration and edge cases."""

    def test_conflicting_strip_options_raises(self):
        with pytest.raises(ValueError, match="strip_non_characters and strip_non_digits cannot both be True"):
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, strip_non_characters=True, strip_non_digits=True)

    def test_conflicting_case_options_raises(self):
        with pytest.raises(ValueError, match="normalize_to_lowercase and normalize_to_uppercase cannot both be True"):
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True, normalize_to_uppercase=True)

    def test_hmac_method_stores_method(self):
        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        assert type_adapter.method == BlindIndexMethod.HMAC_SHA256

    def test_argon2_method_stores_method(self):
        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2)
        assert type_adapter.method == BlindIndexMethod.ARGON2

    def test_missing_secret_key_raises_error(self, monkeypatch):
        from pydantic_encryption.integrations.sqlalchemy import blind_index as blind_index_module

        monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", None)
        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            type_adapter.process_bind_param("test", None)

    def test_different_keys_produce_different_indexes(self, monkeypatch):
        from pydantic_encryption.integrations.sqlalchemy import blind_index as blind_index_module

        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", "key-one")
        result1 = type_adapter.process_bind_param("test@example.com", None)

        monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", "key-two")
        result2 = type_adapter.process_bind_param("test@example.com", None)

        assert result1 != result2

    def test_different_methods_produce_different_outputs(self):
        hmac_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        argon2_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2)
        assert hmac_adapter.process_bind_param("test@example.com", None) != argon2_adapter.process_bind_param("test@example.com", None)

    def test_python_type(self):
        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        assert type_adapter.python_type is type_adapter.impl.python_type


class TestSQLAlchemyBlindIndexValueNormalization:
    """Test SQLAlchemyBlindIndexValue with normalization options."""

    def test_strip_whitespace(self):
        adapter_strip = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, strip_whitespace=True)
        adapter_no_strip = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        result_strip = adapter_strip.process_bind_param("  hello   world  ", None)
        result_normalized = adapter_strip.process_bind_param("hello world", None)
        result_raw = adapter_no_strip.process_bind_param("  hello   world  ", None)

        assert result_strip == result_normalized
        assert result_strip != result_raw

    def test_strip_non_characters(self):
        adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, strip_non_characters=True)

        result1 = adapter.process_bind_param("hello123world!", None)
        result2 = adapter.process_bind_param("helloworld", None)

        assert result1 == result2

    def test_strip_non_digits(self):
        adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, strip_non_digits=True)

        result1 = adapter.process_bind_param("+1 (555) 123-4567", None)
        result2 = adapter.process_bind_param("15551234567", None)

        assert result1 == result2

    def test_normalize_to_lowercase(self):
        adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True)

        result1 = adapter.process_bind_param("Hello@Example.COM", None)
        result2 = adapter.process_bind_param("hello@example.com", None)

        assert result1 == result2

    def test_normalize_to_uppercase(self):
        adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, normalize_to_uppercase=True)

        result1 = adapter.process_bind_param("Hello@Example.com", None)
        result2 = adapter.process_bind_param("HELLO@EXAMPLE.COM", None)

        assert result1 == result2

    def test_combined_normalization(self):
        adapter = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256,
            strip_whitespace=True,
            normalize_to_lowercase=True,
        )

        result1 = adapter.process_bind_param("  Hello@Example.COM  ", None)
        result2 = adapter.process_bind_param("hello@example.com", None)

        assert result1 == result2

    def test_normalization_not_applied_to_bytes(self):
        """Normalization only applies to strings, bytes are passed through as-is."""

        adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True)

        result_bytes = adapter.process_bind_param(b"HELLO", None)
        result_str = adapter.process_bind_param("HELLO", None)

        # bytes won't be lowercased, string will
        assert result_bytes != result_str
