from datetime import date
from decimal import Decimal
from uuid import UUID

from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.integrations.sqlalchemy.serialization import decode_value, encode_value


class TestSQLAlchemyPGEncryptedArray:
    """Test the SQLAlchemyPGEncryptedArray type adapter."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyPGEncryptedArray("tests.encrypted_array.values")

    def test_process_bind_param_none(self):
        assert self.type_adapter.process_bind_param(None, dialect=None) is None

    def test_process_result_value_none(self):
        assert self.type_adapter.process_result_value(None, dialect=None) is None

    def test_process_bind_param_empty_list(self):
        assert self.type_adapter.process_bind_param([], dialect=None) == []

    def test_process_result_value_empty_list(self):
        assert self.type_adapter.process_result_value([], dialect=None) == []

    def test_process_result_value_none_elements(self):
        assert self.type_adapter.process_result_value([None, None], dialect=None) == [None, None]

    def test_element_type_is_sqlalchemy_encrypted(self):
        assert isinstance(self.type_adapter._element_type, SQLAlchemyEncryptedValue)

    def test_python_type_is_list(self):
        assert self.type_adapter.python_type is list

    def test_serialize_deserialize_roundtrip_str_array(self):
        original = ["hello", "world", "test"]
        serialized = [encode_value(v) for v in original]
        result = [decode_value(v) for v in serialized]
        assert result == original

    def test_serialize_deserialize_roundtrip_int_array(self):
        original = [42, -1, 0, 999]
        serialized = [encode_value(v) for v in original]
        result = [decode_value(v) for v in serialized]
        assert result == original

    def test_serialize_deserialize_roundtrip_mixed_types(self):
        original = [42, "hello", 3.14, True, Decimal("99.99")]
        serialized = [encode_value(v) for v in original]
        result = [decode_value(v) for v in serialized]
        assert result == original

    def test_serialize_deserialize_roundtrip_date_array(self):
        original = [date(2025, 1, 1), date(2025, 12, 31)]
        serialized = [encode_value(v) for v in original]
        result = [decode_value(v) for v in serialized]
        assert result == original

    def test_serialize_deserialize_roundtrip_uuid_array(self):
        original = [
            UUID("12345678-1234-5678-1234-567812345678"),
            UUID("87654321-4321-8765-4321-876543218765"),
        ]
        serialized = [encode_value(v) for v in original]
        result = [decode_value(v) for v in serialized]
        assert result == original

    def test_serialize_deserialize_roundtrip_single_element(self):
        original = ["only one"]
        serialized = [encode_value(v) for v in original]
        result = [decode_value(v) for v in serialized]
        assert result == original


class TestPGEncryptedArrayContext:
    """Test that an encrypted array binds its elements to the column's context."""

    def test_element_type_carries_the_context(self):
        """Test that the element type is bound to the context the array was given."""

        assert SQLAlchemyPGEncryptedArray("users.tags")._element_type.context == b"users.tags"

    def test_cache_key_distinguishes_contexts(self):
        """Test that two arrays with different contexts do not share a statement cache key."""

        first = SQLAlchemyPGEncryptedArray("users.tags")
        second = SQLAlchemyPGEncryptedArray("orders.tags")

        assert first._static_cache_key != second._static_cache_key
