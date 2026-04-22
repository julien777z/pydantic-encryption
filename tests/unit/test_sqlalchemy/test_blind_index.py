import pytest

from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue
from tests.unit.test_sqlalchemy.conftest import call_in_greenlet


@pytest.fixture(autouse=True)
def set_blind_index_key(monkeypatch):
    """Set a test blind index secret key for all tests."""

    from pydantic_encryption.integrations.sqlalchemy import blind_index as blind_index_module

    monkeypatch.setattr(
        blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", "test-secret-key-for-blind-index"
    )


def _bind(adapter, value):
    """Run process_bind_param through the greenlet bridge for the test."""

    return call_in_greenlet(adapter.process_bind_param, value, None)


def _literal(adapter, value):
    """Run process_literal_param through the greenlet bridge for the test."""

    return call_in_greenlet(adapter.process_literal_param, value, None)


class TestSQLAlchemyBlindIndexValueHMAC:
    """Test SQLAlchemyBlindIndexValue with HMAC-SHA256 method."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

    def test_process_bind_param_none_returns_none(self):
        """Test that None passes through process_bind_param unchanged."""

        assert self.type_adapter.process_bind_param(None, None) is None

    def test_process_bind_param_string_returns_bytes(self):
        """Test that a string input produces a 32-byte HMAC digest."""

        result = _bind(self.type_adapter, "test@example.com")

        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_bytes_returns_bytes(self):
        """Test that a bytes input produces a 32-byte HMAC digest."""

        result = _bind(self.type_adapter, b"test@example.com")

        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_deterministic(self):
        """Test that equal inputs produce equal digests."""

        assert _bind(self.type_adapter, "test@example.com") == _bind(
            self.type_adapter, "test@example.com"
        )

    def test_process_bind_param_str_bytes_equivalent(self):
        """Test that str and bytes forms of the same value produce the same digest."""

        assert _bind(self.type_adapter, "hello") == _bind(self.type_adapter, b"hello")

    def test_process_bind_param_different_inputs_differ(self):
        """Test that different inputs produce different digests."""

        assert _bind(self.type_adapter, "user1@example.com") != _bind(
            self.type_adapter, "user2@example.com"
        )

    def test_process_literal_param_matches_bind(self):
        """Test that process_literal_param produces the same digest as process_bind_param."""

        assert _bind(self.type_adapter, "test@example.com") == _literal(
            self.type_adapter, "test@example.com"
        )

    def test_process_bind_param_already_indexed_returns_same(self):
        """Test that passing an already-indexed BlindIndexValue to bind returns it unchanged."""

        first = _bind(self.type_adapter, "test@example.com")
        second = _bind(self.type_adapter, BlindIndexValue(first))

        assert first == second

    def test_process_literal_param_already_indexed_returns_same(self):
        """Test that passing an already-indexed BlindIndexValue to literal returns it unchanged."""

        first = _literal(self.type_adapter, "test@example.com")
        second = _literal(self.type_adapter, BlindIndexValue(first))

        assert first == second

    def test_process_literal_param_none_returns_none(self):
        """Test that None passes through process_literal_param unchanged."""

        assert self.type_adapter.process_literal_param(None, None) is None

    def test_process_result_value_none_returns_none(self):
        """Test that None passes through process_result_value unchanged."""

        assert self.type_adapter.process_result_value(None, None) is None

    def test_process_result_value_returns_blind_index_value(self):
        """Test that process_result_value wraps stored bytes as a BlindIndexValue."""

        test_bytes = b"\x01\x02\x03\x04" * 8
        result = self.type_adapter.process_result_value(test_bytes, None)

        assert isinstance(result, BlindIndexValue)
        assert result == test_bytes


class TestSQLAlchemyBlindIndexValueArgon2:
    """Test SQLAlchemyBlindIndexValue with Argon2 method."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2)

    def test_process_bind_param_none_returns_none(self):
        """Test that None passes through process_bind_param unchanged."""

        assert self.type_adapter.process_bind_param(None, None) is None

    def test_process_bind_param_string_returns_bytes(self):
        """Test that an Argon2 digest is 32 bytes."""

        result = _bind(self.type_adapter, "test@example.com")

        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_process_bind_param_deterministic(self):
        """Test that equal inputs produce equal digests."""

        assert _bind(self.type_adapter, "test@example.com") == _bind(
            self.type_adapter, "test@example.com"
        )

    def test_process_bind_param_different_inputs_differ(self):
        """Test that different inputs produce different digests."""

        assert _bind(self.type_adapter, "user1@example.com") != _bind(
            self.type_adapter, "user2@example.com"
        )

    def test_process_bind_param_str_bytes_equivalent(self):
        """Test that str and bytes forms of the same value produce the same digest."""

        assert _bind(self.type_adapter, "hello") == _bind(self.type_adapter, b"hello")


class TestSQLAlchemyBlindIndexValueConfig:
    """Test SQLAlchemyBlindIndexValue configuration and edge cases."""

    def test_conflicting_strip_options_raises(self):
        """Test that contradictory strip options are rejected at construction."""

        with pytest.raises(
            ValueError, match="strip_non_characters and strip_non_digits cannot both be True"
        ):
            SQLAlchemyBlindIndexValue(
                BlindIndexMethod.HMAC_SHA256, strip_non_characters=True, strip_non_digits=True
            )

    def test_conflicting_case_options_raises(self):
        """Test that contradictory case options are rejected at construction."""

        with pytest.raises(
            ValueError, match="normalize_to_lowercase and normalize_to_uppercase cannot both be True"
        ):
            SQLAlchemyBlindIndexValue(
                BlindIndexMethod.HMAC_SHA256,
                normalize_to_lowercase=True,
                normalize_to_uppercase=True,
            )

    def test_hmac_method_stores_method(self):
        """Test that the HMAC-SHA256 method is preserved on the type adapter."""

        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        assert type_adapter.method == BlindIndexMethod.HMAC_SHA256

    def test_argon2_method_stores_method(self):
        """Test that the Argon2 method is preserved on the type adapter."""

        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2)

        assert type_adapter.method == BlindIndexMethod.ARGON2

    def test_missing_secret_key_raises_error(self, monkeypatch):
        """Test that missing BLIND_INDEX_SECRET_KEY raises during bind."""

        from pydantic_encryption.integrations.sqlalchemy import blind_index as blind_index_module

        monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", None)
        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            _bind(type_adapter, "test")

    def test_different_keys_produce_different_indexes(self, monkeypatch):
        """Test that different secret keys produce different digests."""

        from pydantic_encryption.integrations.sqlalchemy import blind_index as blind_index_module

        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", "key-one")
        first = _bind(type_adapter, "test@example.com")

        monkeypatch.setattr(blind_index_module.settings, "BLIND_INDEX_SECRET_KEY", "key-two")
        second = _bind(type_adapter, "test@example.com")

        assert first != second

    def test_different_methods_produce_different_outputs(self):
        """Test that HMAC-SHA256 and Argon2 produce different digests for the same input."""

        hmac_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        argon2_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2)

        assert _bind(hmac_adapter, "test@example.com") != _bind(argon2_adapter, "test@example.com")

    def test_python_type(self):
        """Test that python_type returns the LargeBinary impl's python type."""

        type_adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        assert type_adapter.python_type is type_adapter.impl.python_type


class TestSQLAlchemyBlindIndexValueNormalization:
    """Test SQLAlchemyBlindIndexValue with normalization options."""

    def test_strip_whitespace(self):
        """Test that strip_whitespace normalizes leading/trailing and internal whitespace."""

        adapter_strip = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, strip_whitespace=True
        )
        adapter_no_strip = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        result_strip = _bind(adapter_strip, "  hello   world  ")
        result_normalized = _bind(adapter_strip, "hello world")
        result_raw = _bind(adapter_no_strip, "  hello   world  ")

        assert result_strip == result_normalized
        assert result_strip != result_raw

    def test_strip_non_characters(self):
        """Test that strip_non_characters removes digits and punctuation."""

        adapter = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, strip_non_characters=True
        )

        assert _bind(adapter, "hello123world!") == _bind(adapter, "helloworld")

    def test_strip_non_digits(self):
        """Test that strip_non_digits normalizes formatted numeric strings."""

        adapter = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, strip_non_digits=True)

        assert _bind(adapter, "+1 (555) 123-4567") == _bind(adapter, "15551234567")

    def test_normalize_to_lowercase(self):
        """Test that normalize_to_lowercase produces case-insensitive digests."""

        adapter = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True
        )

        assert _bind(adapter, "Hello@Example.COM") == _bind(adapter, "hello@example.com")

    def test_normalize_to_uppercase(self):
        """Test that normalize_to_uppercase produces case-insensitive digests."""

        adapter = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, normalize_to_uppercase=True
        )

        assert _bind(adapter, "Hello@Example.com") == _bind(adapter, "HELLO@EXAMPLE.COM")

    def test_combined_normalization(self):
        """Test that combined normalization flags compose correctly."""

        adapter = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256,
            strip_whitespace=True,
            normalize_to_lowercase=True,
        )

        assert _bind(adapter, "  Hello@Example.COM  ") == _bind(adapter, "hello@example.com")

    def test_normalization_not_applied_to_bytes(self):
        """Test that normalization only applies to string inputs, not bytes."""

        adapter = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True
        )

        assert _bind(adapter, b"HELLO") != _bind(adapter, "HELLO")
