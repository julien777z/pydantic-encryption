import base64
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import UUID

import pytest

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy._shared import _TypePrefix


class TestSerializeValue:
    """Test the _serialize_value method of SQLAlchemyEncryptedValue."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyEncryptedValue()

    def test_serialize_str(self):
        result = self.type_adapter._serialize_value("hello world")
        assert result == f"v1:{_TypePrefix.STR}:hello world"

    def test_serialize_str_with_colon(self):
        result = self.type_adapter._serialize_value("hello:world")
        assert result == f"v1:{_TypePrefix.STR}:hello:world"

    def test_serialize_bytes(self):
        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        result = self.type_adapter._serialize_value(test_bytes)
        expected_b64 = base64.b64encode(test_bytes).decode("ascii")
        assert result == f"v1:{_TypePrefix.BYTES}:{expected_b64}"

    def test_serialize_bytes_empty(self):
        result = self.type_adapter._serialize_value(b"")
        assert result == f"v1:{_TypePrefix.BYTES}:"

    def test_serialize_int(self):
        result = self.type_adapter._serialize_value(42)
        assert result == f"v1:{_TypePrefix.INT}:42"

    def test_serialize_int_negative(self):
        result = self.type_adapter._serialize_value(-123)
        assert result == f"v1:{_TypePrefix.INT}:-123"

    def test_serialize_bool_true(self):
        result = self.type_adapter._serialize_value(True)
        assert result == f"v1:{_TypePrefix.BOOL}:true"

    def test_serialize_bool_false(self):
        result = self.type_adapter._serialize_value(False)
        assert result == f"v1:{_TypePrefix.BOOL}:false"

    def test_serialize_date(self):
        result = self.type_adapter._serialize_value(date(2025, 1, 21))
        assert result == f"v1:{_TypePrefix.DATE}:2025-01-21"

    def test_serialize_datetime(self):
        result = self.type_adapter._serialize_value(datetime(2025, 1, 21, 14, 30, 45))
        assert result == f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45"

    def test_serialize_datetime_with_timezone(self):
        result = self.type_adapter._serialize_value(datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc))
        assert result == f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"

    def test_serialize_time(self):
        result = self.type_adapter._serialize_value(time(14, 30, 45))
        assert result == f"v1:{_TypePrefix.TIME}:14:30:45"

    def test_serialize_time_with_microseconds(self):
        result = self.type_adapter._serialize_value(time(14, 30, 45, 123456))
        assert result == f"v1:{_TypePrefix.TIME}:14:30:45.123456"

    def test_serialize_time_with_timezone(self):
        result = self.type_adapter._serialize_value(time(14, 30, 45, tzinfo=timezone.utc))
        assert result == f"v1:{_TypePrefix.TIME}:14:30:45+00:00"

    def test_serialize_timedelta(self):
        td = timedelta(days=1, hours=2, minutes=30, seconds=45)
        result = self.type_adapter._serialize_value(td)
        assert result == f"v1:{_TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_timedelta_negative(self):
        td = timedelta(days=-1, hours=-2)
        result = self.type_adapter._serialize_value(td)
        assert result == f"v1:{_TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_timedelta_fractional(self):
        td = timedelta(seconds=1.5)
        result = self.type_adapter._serialize_value(td)
        assert result == f"v1:{_TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_float(self):
        result = self.type_adapter._serialize_value(3.14159)
        assert result == f"v1:{_TypePrefix.FLOAT}:3.14159"

    def test_serialize_float_negative(self):
        result = self.type_adapter._serialize_value(-2.5)
        assert result == f"v1:{_TypePrefix.FLOAT}:-2.5"

    def test_serialize_float_scientific(self):
        result = self.type_adapter._serialize_value(1e-10)
        assert result == f"v1:{_TypePrefix.FLOAT}:1e-10"

    def test_serialize_decimal(self):
        result = self.type_adapter._serialize_value(Decimal("123.456789"))
        assert result == f"v1:{_TypePrefix.DECIMAL}:123.456789"

    def test_serialize_decimal_high_precision(self):
        result = self.type_adapter._serialize_value(Decimal("0.123456789012345678901234567890"))
        assert result == f"v1:{_TypePrefix.DECIMAL}:0.123456789012345678901234567890"

    def test_serialize_decimal_negative(self):
        result = self.type_adapter._serialize_value(Decimal("-999.99"))
        assert result == f"v1:{_TypePrefix.DECIMAL}:-999.99"

    def test_serialize_uuid(self):
        result = self.type_adapter._serialize_value(UUID("12345678-1234-5678-1234-567812345678"))
        assert result == f"v1:{_TypePrefix.UUID}:12345678-1234-5678-1234-567812345678"


class TestDeserializeValue:
    """Test the _deserialize_value method of SQLAlchemyEncryptedValue."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyEncryptedValue()

    def test_deserialize_str(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.STR}:hello world")
        assert result == "hello world"
        assert isinstance(result, str)

    def test_deserialize_str_with_colon(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.STR}:hello:world")
        assert result == "hello:world"

    def test_deserialize_bytes(self):
        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        encoded = base64.b64encode(test_bytes).decode("ascii")
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BYTES}:{encoded}")
        assert result == test_bytes
        assert isinstance(result, bytes)

    def test_deserialize_bytes_empty(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BYTES}:")
        assert result == b""
        assert isinstance(result, bytes)

    def test_deserialize_int(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.INT}:42")
        assert result == 42
        assert isinstance(result, int)

    def test_deserialize_int_negative(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.INT}:-123")
        assert result == -123

    def test_deserialize_bool_true(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BOOL}:true")
        assert result is True
        assert isinstance(result, bool)

    def test_deserialize_bool_false(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.BOOL}:false")
        assert result is False
        assert isinstance(result, bool)

    def test_deserialize_date(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DATE}:2025-01-21")
        assert result == date(2025, 1, 21)
        assert isinstance(result, date)
        assert not isinstance(result, datetime)

    def test_deserialize_datetime(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45")
        assert result == datetime(2025, 1, 21, 14, 30, 45)
        assert isinstance(result, datetime)

    def test_deserialize_datetime_with_timezone(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00")
        assert result == datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_time(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIME}:14:30:45")
        assert result == time(14, 30, 45)
        assert isinstance(result, time)

    def test_deserialize_time_with_microseconds(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIME}:14:30:45.123456")
        assert result == time(14, 30, 45, 123456)

    def test_deserialize_time_with_timezone(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIME}:14:30:45+00:00")
        assert result == time(14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_timedelta(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIMEDELTA}:1,9045,0")
        assert result == timedelta(days=1, hours=2, minutes=30, seconds=45)
        assert isinstance(result, timedelta)

    def test_deserialize_timedelta_negative(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIMEDELTA}:-2,79200,0")
        assert result == timedelta(days=-1, hours=-2)

    def test_deserialize_timedelta_fractional(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.TIMEDELTA}:0,1,500000")
        assert result == timedelta(seconds=1.5)

    def test_deserialize_float(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.FLOAT}:3.14159")
        assert result == 3.14159
        assert isinstance(result, float)

    def test_deserialize_float_negative(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.FLOAT}:-2.5")
        assert result == -2.5

    def test_deserialize_float_scientific(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.FLOAT}:1e-10")
        assert result == 1e-10

    def test_deserialize_decimal(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DECIMAL}:123.456789")
        assert result == Decimal("123.456789")
        assert isinstance(result, Decimal)

    def test_deserialize_decimal_high_precision(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DECIMAL}:0.123456789012345678901234567890")
        assert result == Decimal("0.123456789012345678901234567890")

    def test_deserialize_decimal_negative(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.DECIMAL}:-999.99")
        assert result == Decimal("-999.99")

    def test_deserialize_uuid(self):
        result = self.type_adapter._deserialize_value(f"v1:{_TypePrefix.UUID}:12345678-1234-5678-1234-567812345678")
        assert result == UUID("12345678-1234-5678-1234-567812345678")
        assert isinstance(result, UUID)

    def test_deserialize_legacy_format_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            self.type_adapter._deserialize_value("str:hello world")

    def test_deserialize_unknown_version_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            self.type_adapter._deserialize_value("v2:str:hello world")

    def test_deserialize_no_colon_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            self.type_adapter._deserialize_value("no_colon_here")


class TestSerializeDeserializeRoundTrip:
    """Test round-trip serialization and deserialization."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyEncryptedValue()

    def test_roundtrip_str(self):
        original = "hello world"
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_bytes(self):
        original = b"\x00\x01\x02\x03binary\xff\xfe"
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_int(self):
        original = -12345
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_bool_true(self):
        original = True
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result is True
        assert isinstance(result, bool)

    def test_roundtrip_bool_false(self):
        original = False
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result is False
        assert isinstance(result, bool)

    def test_roundtrip_date(self):
        original = date(2025, 1, 21)
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_datetime(self):
        original = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_time(self):
        original = time(14, 30, 45, 123456, tzinfo=timezone.utc)
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_timedelta(self):
        original = timedelta(days=5, hours=3, minutes=30, seconds=45, microseconds=123456)
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_timedelta_negative(self):
        original = timedelta(days=-10, hours=-5)
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_float(self):
        original = 3.141592653589793
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original

    def test_roundtrip_decimal(self):
        original = Decimal("123.456789012345678901234567890")
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original
        assert isinstance(result, Decimal)

    def test_roundtrip_uuid(self):
        original = UUID("12345678-1234-5678-1234-567812345678")
        result = self.type_adapter._deserialize_value(self.type_adapter._serialize_value(original))
        assert result == original
        assert isinstance(result, UUID)
