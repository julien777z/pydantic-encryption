import base64
from datetime import date, datetime, timezone

import pytest

from pydantic_encryption.integrations.sqlalchemy import SQLAlchemyEncrypted, _TypePrefix


class TestSerializeValue:
    """Test the _serialize_value method of SQLAlchemyEncrypted."""

    def setup_method(self):
        """Set up test fixtures."""

        self.type_adapter = SQLAlchemyEncrypted()

    def test_serialize_str(self):
        """Test serializing a string value."""

        result = self.type_adapter._serialize_value("hello world")

        assert result == f"{_TypePrefix.STR}:hello world"

    def test_serialize_str_with_colon(self):
        """Test serializing a string with colon preserves the colon."""

        result = self.type_adapter._serialize_value("hello:world")

        assert result == f"{_TypePrefix.STR}:hello:world"

    def test_serialize_bytes(self):
        """Test serializing bytes value."""

        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"

        result = self.type_adapter._serialize_value(test_bytes)

        expected_b64 = base64.b64encode(test_bytes).decode("ascii")
        assert result == f"{_TypePrefix.BYTES}:{expected_b64}"

    def test_serialize_bytes_empty(self):
        """Test serializing empty bytes."""

        result = self.type_adapter._serialize_value(b"")

        assert result == f"{_TypePrefix.BYTES}:"

    def test_serialize_int(self):
        """Test serializing an integer value."""

        result = self.type_adapter._serialize_value(42)

        assert result == f"{_TypePrefix.INT}:42"

    def test_serialize_int_negative(self):
        """Test serializing a negative integer."""

        result = self.type_adapter._serialize_value(-123)

        assert result == f"{_TypePrefix.INT}:-123"

    def test_serialize_date(self):
        """Test serializing a date value."""

        test_date = date(2025, 1, 21)

        result = self.type_adapter._serialize_value(test_date)

        assert result == f"{_TypePrefix.DATE}:2025-01-21"

    def test_serialize_datetime(self):
        """Test serializing a datetime value."""

        test_datetime = datetime(2025, 1, 21, 14, 30, 45)

        result = self.type_adapter._serialize_value(test_datetime)

        assert result == f"{_TypePrefix.DATETIME}:2025-01-21T14:30:45"

    def test_serialize_datetime_with_timezone(self):
        """Test serializing a timezone-aware datetime."""

        test_datetime = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)

        result = self.type_adapter._serialize_value(test_datetime)

        assert result == f"{_TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"


class TestDeserializeValue:
    """Test the _deserialize_value method of SQLAlchemyEncrypted."""

    def setup_method(self):
        """Set up test fixtures."""

        self.type_adapter = SQLAlchemyEncrypted()

    def test_deserialize_str(self):
        """Test deserializing a string value."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.STR}:hello world")

        assert result == "hello world"
        assert isinstance(result, str)

    def test_deserialize_str_with_colon(self):
        """Test deserializing a string with colon."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.STR}:hello:world")

        assert result == "hello:world"

    def test_deserialize_bytes(self):
        """Test deserializing bytes value."""

        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        encoded = base64.b64encode(test_bytes).decode("ascii")

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.BYTES}:{encoded}")

        assert result == test_bytes
        assert isinstance(result, bytes)

    def test_deserialize_bytes_empty(self):
        """Test deserializing empty bytes."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.BYTES}:")

        assert result == b""
        assert isinstance(result, bytes)

    def test_deserialize_int(self):
        """Test deserializing an integer value."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.INT}:42")

        assert result == 42
        assert isinstance(result, int)

    def test_deserialize_int_negative(self):
        """Test deserializing a negative integer."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.INT}:-123")

        assert result == -123

    def test_deserialize_date(self):
        """Test deserializing a date value."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.DATE}:2025-01-21")

        assert result == date(2025, 1, 21)
        assert isinstance(result, date)
        assert not isinstance(result, datetime)

    def test_deserialize_datetime(self):
        """Test deserializing a datetime value."""

        result = self.type_adapter._deserialize_value(f"{_TypePrefix.DATETIME}:2025-01-21T14:30:45")

        assert result == datetime(2025, 1, 21, 14, 30, 45)
        assert isinstance(result, datetime)

    def test_deserialize_datetime_with_timezone(self):
        """Test deserializing a timezone-aware datetime."""

        result = self.type_adapter._deserialize_value(
            f"{_TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"
        )

        assert result == datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_unknown_prefix_returns_original(self):
        """Test that unknown prefix returns the original value unchanged."""

        result = self.type_adapter._deserialize_value("unknown:some data")

        assert result == "unknown:some data"

    def test_deserialize_no_colon_returns_original(self):
        """Test that value without colon returns the original value."""

        result = self.type_adapter._deserialize_value("no_colon_here")

        assert result == "no_colon_here"


class TestSerializeDeserializeRoundTrip:
    """Test round-trip serialization and deserialization."""

    def setup_method(self):
        """Set up test fixtures."""

        self.type_adapter = SQLAlchemyEncrypted()

    def test_roundtrip_str(self):
        """Test round-trip for string."""

        original = "hello world"

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_bytes(self):
        """Test round-trip for bytes."""

        original = b"\x00\x01\x02\x03binary\xff\xfe"

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_int(self):
        """Test round-trip for integer."""

        original = -12345

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_date(self):
        """Test round-trip for date."""

        original = date(2025, 1, 21)

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_datetime(self):
        """Test round-trip for datetime."""

        original = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original
