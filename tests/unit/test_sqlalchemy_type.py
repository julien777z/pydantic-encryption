import base64
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import UUID

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

        assert result == f"v1:{_TypePrefix.STR}:hello world"

    def test_serialize_str_with_colon(self):
        """Test serializing a string with colon preserves the colon."""

        result = self.type_adapter._serialize_value("hello:world")

        assert result == f"v1:{_TypePrefix.STR}:hello:world"

    def test_serialize_bytes(self):
        """Test serializing bytes value."""

        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"

        result = self.type_adapter._serialize_value(test_bytes)

        expected_b64 = base64.b64encode(test_bytes).decode("ascii")
        assert result == f"v1:{_TypePrefix.BYTES}:{expected_b64}"

    def test_serialize_bytes_empty(self):
        """Test serializing empty bytes."""

        result = self.type_adapter._serialize_value(b"")

        assert result == f"v1:{_TypePrefix.BYTES}:"

    def test_serialize_int(self):
        """Test serializing an integer value."""

        result = self.type_adapter._serialize_value(42)

        assert result == f"v1:{_TypePrefix.INT}:42"

    def test_serialize_int_negative(self):
        """Test serializing a negative integer."""

        result = self.type_adapter._serialize_value(-123)

        assert result == f"v1:{_TypePrefix.INT}:-123"

    def test_serialize_bool_true(self):
        """Test serializing boolean True."""

        result = self.type_adapter._serialize_value(True)

        assert result == f"v1:{_TypePrefix.BOOL}:true"

    def test_serialize_bool_false(self):
        """Test serializing boolean False."""

        result = self.type_adapter._serialize_value(False)

        assert result == f"v1:{_TypePrefix.BOOL}:false"

    def test_serialize_date(self):
        """Test serializing a date value."""

        test_date = date(2025, 1, 21)

        result = self.type_adapter._serialize_value(test_date)

        assert result == f"v1:{_TypePrefix.DATE}:2025-01-21"

    def test_serialize_datetime(self):
        """Test serializing a datetime value."""

        test_datetime = datetime(2025, 1, 21, 14, 30, 45)

        result = self.type_adapter._serialize_value(test_datetime)

        assert result == f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45"

    def test_serialize_datetime_with_timezone(self):
        """Test serializing a timezone-aware datetime."""

        test_datetime = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)

        result = self.type_adapter._serialize_value(test_datetime)

        assert result == f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"

    def test_serialize_time(self):
        """Test serializing a time value."""

        test_time = time(14, 30, 45)

        result = self.type_adapter._serialize_value(test_time)

        assert result == f"v1:{_TypePrefix.TIME}:14:30:45"

    def test_serialize_time_with_microseconds(self):
        """Test serializing a time with microseconds."""

        test_time = time(14, 30, 45, 123456)

        result = self.type_adapter._serialize_value(test_time)

        assert result == f"v1:{_TypePrefix.TIME}:14:30:45.123456"

    def test_serialize_time_with_timezone(self):
        """Test serializing a timezone-aware time."""

        test_time = time(14, 30, 45, tzinfo=timezone.utc)

        result = self.type_adapter._serialize_value(test_time)

        assert result == f"v1:{_TypePrefix.TIME}:14:30:45+00:00"

    def test_serialize_timedelta(self):
        """Test serializing a timedelta value."""

        test_timedelta = timedelta(days=1, hours=2, minutes=30, seconds=45)

        result = self.type_adapter._serialize_value(test_timedelta)

        # Format: days,seconds,microseconds to preserve precision
        assert result == f"v1:{_TypePrefix.TIMEDELTA}:{test_timedelta.days},{test_timedelta.seconds},{test_timedelta.microseconds}"

    def test_serialize_timedelta_negative(self):
        """Test serializing a negative timedelta."""

        test_timedelta = timedelta(days=-1, hours=-2)

        result = self.type_adapter._serialize_value(test_timedelta)

        # Format: days,seconds,microseconds to preserve precision
        assert result == f"v1:{_TypePrefix.TIMEDELTA}:{test_timedelta.days},{test_timedelta.seconds},{test_timedelta.microseconds}"

    def test_serialize_timedelta_fractional(self):
        """Test serializing a timedelta with fractional seconds (stored as microseconds)."""

        test_timedelta = timedelta(seconds=1.5)

        result = self.type_adapter._serialize_value(test_timedelta)

        # Format: days,seconds,microseconds - fractional seconds become microseconds
        assert result == f"v1:{_TypePrefix.TIMEDELTA}:{test_timedelta.days},{test_timedelta.seconds},{test_timedelta.microseconds}"

    def test_serialize_float(self):
        """Test serializing a float value."""

        result = self.type_adapter._serialize_value(3.14159)

        assert result == f"v1:{_TypePrefix.FLOAT}:3.14159"

    def test_serialize_float_negative(self):
        """Test serializing a negative float."""

        result = self.type_adapter._serialize_value(-2.5)

        assert result == f"v1:{_TypePrefix.FLOAT}:-2.5"

    def test_serialize_float_scientific(self):
        """Test serializing a float in scientific notation."""

        result = self.type_adapter._serialize_value(1e-10)

        assert result == f"v1:{_TypePrefix.FLOAT}:1e-10"

    def test_serialize_decimal(self):
        """Test serializing a Decimal value."""

        test_decimal = Decimal("123.456789")

        result = self.type_adapter._serialize_value(test_decimal)

        assert result == f"v1:{_TypePrefix.DECIMAL}:123.456789"

    def test_serialize_decimal_high_precision(self):
        """Test serializing a high-precision Decimal."""

        test_decimal = Decimal("0.123456789012345678901234567890")

        result = self.type_adapter._serialize_value(test_decimal)

        assert result == f"v1:{_TypePrefix.DECIMAL}:0.123456789012345678901234567890"

    def test_serialize_decimal_negative(self):
        """Test serializing a negative Decimal."""

        test_decimal = Decimal("-999.99")

        result = self.type_adapter._serialize_value(test_decimal)

        assert result == f"v1:{_TypePrefix.DECIMAL}:-999.99"

    def test_serialize_uuid(self):
        """Test serializing a UUID value."""

        test_uuid = UUID("12345678-1234-5678-1234-567812345678")

        result = self.type_adapter._serialize_value(test_uuid)

        assert result == f"v1:{_TypePrefix.UUID}:12345678-1234-5678-1234-567812345678"


class TestDeserializeValue:
    """Test the _deserialize_value method of SQLAlchemyEncrypted."""

    def setup_method(self):
        """Set up test fixtures."""

        self.type_adapter = SQLAlchemyEncrypted()

    def test_deserialize_str(self):
        """Test deserializing a string value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.STR}:hello world")

        assert result == "hello world"
        assert isinstance(result, str)

    def test_deserialize_str_with_colon(self):
        """Test deserializing a string with colon."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.STR}:hello:world")

        assert result == "hello:world"

    def test_deserialize_bytes(self):
        """Test deserializing bytes value."""

        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        encoded = base64.b64encode(test_bytes).decode("ascii")

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BYTES}:{encoded}")

        assert result == test_bytes
        assert isinstance(result, bytes)

    def test_deserialize_bytes_empty(self):
        """Test deserializing empty bytes."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BYTES}:")

        assert result == b""
        assert isinstance(result, bytes)

    def test_deserialize_int(self):
        """Test deserializing an integer value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.INT}:42")

        assert result == 42
        assert isinstance(result, int)

    def test_deserialize_int_negative(self):
        """Test deserializing a negative integer."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.INT}:-123")

        assert result == -123

    def test_deserialize_bool_true(self):
        """Test deserializing boolean True."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BOOL}:true")

        assert result is True
        assert isinstance(result, bool)

    def test_deserialize_bool_false(self):
        """Test deserializing boolean False."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BOOL}:false")

        assert result is False
        assert isinstance(result, bool)

    def test_deserialize_date(self):
        """Test deserializing a date value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DATE}:2025-01-21")

        assert result == date(2025, 1, 21)
        assert isinstance(result, date)
        assert not isinstance(result, datetime)

    def test_deserialize_datetime(self):
        """Test deserializing a datetime value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45")

        assert result == datetime(2025, 1, 21, 14, 30, 45)
        assert isinstance(result, datetime)

    def test_deserialize_datetime_with_timezone(self):
        """Test deserializing a timezone-aware datetime."""

        result = self.type_adapter._deserialize_value(
            f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"
        )

        assert result == datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_time(self):
        """Test deserializing a time value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIME}:14:30:45")

        assert result == time(14, 30, 45)
        assert isinstance(result, time)

    def test_deserialize_time_with_microseconds(self):
        """Test deserializing a time with microseconds."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIME}:14:30:45.123456")

        assert result == time(14, 30, 45, 123456)

    def test_deserialize_time_with_timezone(self):
        """Test deserializing a timezone-aware time."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIME}:14:30:45+00:00")

        assert result == time(14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_timedelta(self):
        """Test deserializing a timedelta value."""

        # timedelta(days=1, hours=2, minutes=30, seconds=45) -> days=1, seconds=9045, microseconds=0
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIMEDELTA}:1,9045,0")

        assert result == timedelta(days=1, hours=2, minutes=30, seconds=45)
        assert isinstance(result, timedelta)

    def test_deserialize_timedelta_negative(self):
        """Test deserializing a negative timedelta."""

        # timedelta(days=-1, hours=-2) normalizes to days=-2, seconds=79200, microseconds=0
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIMEDELTA}:-2,79200,0")

        assert result == timedelta(days=-1, hours=-2)

    def test_deserialize_timedelta_fractional(self):
        """Test deserializing a timedelta with fractional seconds."""

        # timedelta(seconds=1.5) -> days=0, seconds=1, microseconds=500000
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIMEDELTA}:0,1,500000")

        assert result == timedelta(seconds=1.5)

    def test_deserialize_float(self):
        """Test deserializing a float value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.FLOAT}:3.14159")

        assert result == 3.14159
        assert isinstance(result, float)

    def test_deserialize_float_negative(self):
        """Test deserializing a negative float."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.FLOAT}:-2.5")

        assert result == -2.5

    def test_deserialize_float_scientific(self):
        """Test deserializing a float in scientific notation."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.FLOAT}:1e-10")

        assert result == 1e-10

    def test_deserialize_decimal(self):
        """Test deserializing a Decimal value."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DECIMAL}:123.456789")

        assert result == Decimal("123.456789")
        assert isinstance(result, Decimal)

    def test_deserialize_decimal_high_precision(self):
        """Test deserializing a high-precision Decimal."""

        result = self.type_adapter._deserialize_value(
            f"v1:{_TypePrefix.DECIMAL}:0.123456789012345678901234567890"
        )

        assert result == Decimal("0.123456789012345678901234567890")

    def test_deserialize_decimal_negative(self):
        """Test deserializing a negative Decimal."""

        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DECIMAL}:-999.99")

        assert result == Decimal("-999.99")

    def test_deserialize_uuid(self):
        """Test deserializing a UUID value."""

        result = self.type_adapter._deserialize_value(
            f"v1:{_TypePrefix.UUID}:12345678-1234-5678-1234-567812345678"
        )

        assert result == UUID("12345678-1234-5678-1234-567812345678")
        assert isinstance(result, UUID)

    def test_deserialize_legacy_format_raises_error(self):
        """Test that legacy format without version marker raises RuntimeError."""

        with pytest.raises(RuntimeError, match="Unknown version"):
            self.type_adapter._deserialize_value("str:hello world")

    def test_deserialize_unknown_version_raises_error(self):
        """Test that unknown version raises RuntimeError."""

        with pytest.raises(RuntimeError, match="Unknown version"):
            self.type_adapter._deserialize_value("v2:str:hello world")

    def test_deserialize_no_colon_raises_error(self):
        """Test that value without colon raises RuntimeError."""

        with pytest.raises(RuntimeError, match="Unknown version"):
            self.type_adapter._deserialize_value("no_colon_here")


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

    def test_roundtrip_bool_true(self):
        """Test round-trip for boolean True."""

        original = True

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result is True
        assert isinstance(result, bool)

    def test_roundtrip_bool_false(self):
        """Test round-trip for boolean False."""

        original = False

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result is False
        assert isinstance(result, bool)

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

    def test_roundtrip_time(self):
        """Test round-trip for time."""

        original = time(14, 30, 45, 123456, tzinfo=timezone.utc)

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_timedelta(self):
        """Test round-trip for timedelta."""

        original = timedelta(days=5, hours=3, minutes=30, seconds=45, microseconds=123456)

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_timedelta_negative(self):
        """Test round-trip for negative timedelta."""

        original = timedelta(days=-10, hours=-5)

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_float(self):
        """Test round-trip for float."""

        original = 3.141592653589793

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original

    def test_roundtrip_decimal(self):
        """Test round-trip for Decimal."""

        original = Decimal("123.456789012345678901234567890")

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original
        assert isinstance(result, Decimal)

    def test_roundtrip_uuid(self):
        """Test round-trip for UUID."""

        original = UUID("12345678-1234-5678-1234-567812345678")

        serialized = self.type_adapter._serialize_value(original)
        result = self.type_adapter._deserialize_value(serialized)

        assert result == original
        assert isinstance(result, UUID)
