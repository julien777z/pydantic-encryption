import base64
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import UUID

import pytest

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.serialization import (
    TypePrefix,
    decode_value,
    encode_value,
)


class TestEncodeValue:
    """Test ``encode_value`` serialization."""

    def test_serialize_str(self):
        result = encode_value("hello world")
        assert result == f"v1:{TypePrefix.STR}:hello world"

    def test_serialize_str_with_colon(self):
        result = encode_value("hello:world")
        assert result == f"v1:{TypePrefix.STR}:hello:world"

    def test_serialize_bytes(self):
        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        result = encode_value(test_bytes)
        expected_b64 = base64.b64encode(test_bytes).decode("ascii")
        assert result == f"v1:{TypePrefix.BYTES}:{expected_b64}"

    def test_serialize_bytes_empty(self):
        result = encode_value(b"")
        assert result == f"v1:{TypePrefix.BYTES}:"

    def test_serialize_int(self):
        result = encode_value(42)
        assert result == f"v1:{TypePrefix.INT}:42"

    def test_serialize_int_negative(self):
        result = encode_value(-123)
        assert result == f"v1:{TypePrefix.INT}:-123"

    def test_serialize_bool_true(self):
        result = encode_value(True)
        assert result == f"v1:{TypePrefix.BOOL}:true"

    def test_serialize_bool_false(self):
        result = encode_value(False)
        assert result == f"v1:{TypePrefix.BOOL}:false"

    def test_serialize_date(self):
        result = encode_value(date(2025, 1, 21))
        assert result == f"v1:{TypePrefix.DATE}:2025-01-21"

    def test_serialize_datetime(self):
        result = encode_value(datetime(2025, 1, 21, 14, 30, 45))
        assert result == f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45"

    def test_serialize_datetime_with_timezone(self):
        result = encode_value(datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc))
        assert result == f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"

    def test_serialize_time(self):
        result = encode_value(time(14, 30, 45))
        assert result == f"v1:{TypePrefix.TIME}:14:30:45"

    def test_serialize_time_with_microseconds(self):
        result = encode_value(time(14, 30, 45, 123456))
        assert result == f"v1:{TypePrefix.TIME}:14:30:45.123456"

    def test_serialize_time_with_timezone(self):
        result = encode_value(time(14, 30, 45, tzinfo=timezone.utc))
        assert result == f"v1:{TypePrefix.TIME}:14:30:45+00:00"

    def test_serialize_timedelta(self):
        td = timedelta(days=1, hours=2, minutes=30, seconds=45)
        result = encode_value(td)
        assert result == f"v1:{TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_timedelta_negative(self):
        td = timedelta(days=-1, hours=-2)
        result = encode_value(td)
        assert result == f"v1:{TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_timedelta_fractional(self):
        td = timedelta(seconds=1.5)
        result = encode_value(td)
        assert result == f"v1:{TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_float(self):
        result = encode_value(3.14159)
        assert result == f"v1:{TypePrefix.FLOAT}:3.14159"

    def test_serialize_float_negative(self):
        result = encode_value(-2.5)
        assert result == f"v1:{TypePrefix.FLOAT}:-2.5"

    def test_serialize_float_scientific(self):
        result = encode_value(1e-10)
        assert result == f"v1:{TypePrefix.FLOAT}:1e-10"

    def test_serialize_decimal(self):
        result = encode_value(Decimal("123.456789"))
        assert result == f"v1:{TypePrefix.DECIMAL}:123.456789"

    def test_serialize_decimal_high_precision(self):
        result = encode_value(Decimal("0.123456789012345678901234567890"))
        assert result == f"v1:{TypePrefix.DECIMAL}:0.123456789012345678901234567890"

    def test_serialize_decimal_negative(self):
        result = encode_value(Decimal("-999.99"))
        assert result == f"v1:{TypePrefix.DECIMAL}:-999.99"

    def test_serialize_uuid(self):
        result = encode_value(UUID("12345678-1234-5678-1234-567812345678"))
        assert result == f"v1:{TypePrefix.UUID}:12345678-1234-5678-1234-567812345678"


class TestDecodeValue:
    """Test ``decode_value`` deserialization."""

    def test_deserialize_str(self):
        result = decode_value(f"v1:{TypePrefix.STR}:hello world")
        assert result == "hello world"
        assert isinstance(result, str)

    def test_deserialize_str_with_colon(self):
        result = decode_value(f"v1:{TypePrefix.STR}:hello:world")
        assert result == "hello:world"

    def test_deserialize_bytes(self):
        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        encoded = base64.b64encode(test_bytes).decode("ascii")
        result = decode_value(f"v1:{TypePrefix.BYTES}:{encoded}")
        assert result == test_bytes
        assert isinstance(result, bytes)

    def test_deserialize_bytes_empty(self):
        result = decode_value(f"v1:{TypePrefix.BYTES}:")
        assert result == b""
        assert isinstance(result, bytes)

    def test_deserialize_int(self):
        result = decode_value(f"v1:{TypePrefix.INT}:42")
        assert result == 42
        assert isinstance(result, int)

    def test_deserialize_int_negative(self):
        result = decode_value(f"v1:{TypePrefix.INT}:-123")
        assert result == -123

    def test_deserialize_bool_true(self):
        result = decode_value(f"v1:{TypePrefix.BOOL}:true")
        assert result is True
        assert isinstance(result, bool)

    def test_deserialize_bool_false(self):
        result = decode_value(f"v1:{TypePrefix.BOOL}:false")
        assert result is False
        assert isinstance(result, bool)

    def test_deserialize_date(self):
        result = decode_value(f"v1:{TypePrefix.DATE}:2025-01-21")
        assert result == date(2025, 1, 21)
        assert isinstance(result, date)
        assert not isinstance(result, datetime)

    def test_deserialize_datetime(self):
        result = decode_value(f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45")
        assert result == datetime(2025, 1, 21, 14, 30, 45)
        assert isinstance(result, datetime)

    def test_deserialize_datetime_with_timezone(self):
        result = decode_value(f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00")
        assert result == datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_time(self):
        result = decode_value(f"v1:{TypePrefix.TIME}:14:30:45")
        assert result == time(14, 30, 45)
        assert isinstance(result, time)

    def test_deserialize_time_with_microseconds(self):
        result = decode_value(f"v1:{TypePrefix.TIME}:14:30:45.123456")
        assert result == time(14, 30, 45, 123456)

    def test_deserialize_time_with_timezone(self):
        result = decode_value(f"v1:{TypePrefix.TIME}:14:30:45+00:00")
        assert result == time(14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_timedelta(self):
        result = decode_value(f"v1:{TypePrefix.TIMEDELTA}:1,9045,0")
        assert result == timedelta(days=1, hours=2, minutes=30, seconds=45)
        assert isinstance(result, timedelta)

    def test_deserialize_timedelta_negative(self):
        result = decode_value(f"v1:{TypePrefix.TIMEDELTA}:-2,79200,0")
        assert result == timedelta(days=-1, hours=-2)

    def test_deserialize_timedelta_fractional(self):
        result = decode_value(f"v1:{TypePrefix.TIMEDELTA}:0,1,500000")
        assert result == timedelta(seconds=1.5)

    def test_deserialize_float(self):
        result = decode_value(f"v1:{TypePrefix.FLOAT}:3.14159")
        assert result == 3.14159
        assert isinstance(result, float)

    def test_deserialize_float_negative(self):
        result = decode_value(f"v1:{TypePrefix.FLOAT}:-2.5")
        assert result == -2.5

    def test_deserialize_float_scientific(self):
        result = decode_value(f"v1:{TypePrefix.FLOAT}:1e-10")
        assert result == 1e-10

    def test_deserialize_decimal(self):
        result = decode_value(f"v1:{TypePrefix.DECIMAL}:123.456789")
        assert result == Decimal("123.456789")
        assert isinstance(result, Decimal)

    def test_deserialize_decimal_high_precision(self):
        result = decode_value(f"v1:{TypePrefix.DECIMAL}:0.123456789012345678901234567890")
        assert result == Decimal("0.123456789012345678901234567890")

    def test_deserialize_decimal_negative(self):
        result = decode_value(f"v1:{TypePrefix.DECIMAL}:-999.99")
        assert result == Decimal("-999.99")

    def test_deserialize_uuid(self):
        result = decode_value(f"v1:{TypePrefix.UUID}:12345678-1234-5678-1234-567812345678")
        assert result == UUID("12345678-1234-5678-1234-567812345678")
        assert isinstance(result, UUID)

    def test_deserialize_legacy_format_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("str:hello world")

    def test_deserialize_unknown_version_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("v2:str:hello world")

    def test_deserialize_no_colon_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("no_colon_here")


class TestRoundTrip:
    """Test round-trip ``encode_value`` / ``decode_value``."""

    def test_roundtrip_str(self):
        original = "hello world"
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_bytes(self):
        original = b"\x00\x01\x02\x03binary\xff\xfe"
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_int(self):
        original = -12345
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_bool_true(self):
        result = decode_value(encode_value(True))
        assert result is True
        assert isinstance(result, bool)

    def test_roundtrip_bool_false(self):
        result = decode_value(encode_value(False))
        assert result is False
        assert isinstance(result, bool)

    def test_roundtrip_date(self):
        original = date(2025, 1, 21)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_datetime(self):
        original = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_time(self):
        original = time(14, 30, 45, 123456, tzinfo=timezone.utc)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_timedelta(self):
        original = timedelta(days=5, hours=3, minutes=30, seconds=45, microseconds=123456)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_timedelta_negative(self):
        original = timedelta(days=-10, hours=-5)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_float(self):
        original = 3.141592653589793
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_decimal(self):
        original = Decimal("123.456789012345678901234567890")
        result = decode_value(encode_value(original))
        assert result == original
        assert isinstance(result, Decimal)

    def test_roundtrip_uuid(self):
        original = UUID("12345678-1234-5678-1234-567812345678")
        result = decode_value(encode_value(original))
        assert result == original
        assert isinstance(result, UUID)


class TestEncryptionIdempotency:
    """Test that already-encrypted values are not re-encrypted."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyEncryptedValue()

    def test_encrypt_cell_already_encrypted_returns_same(self):
        """Test that an EncryptedValue passed to _encrypt_cell is returned unchanged."""

        from tests.unit.test_sqlalchemy.conftest import call_in_greenlet

        encrypted = call_in_greenlet(self.type_adapter._encrypt_cell, "hello")
        double_encrypted = call_in_greenlet(self.type_adapter._encrypt_cell, encrypted)

        assert encrypted == double_encrypted

    def test_process_bind_param_already_encrypted_returns_same(self):
        """Test that an already-encrypted value skipped by process_bind_param is returned unchanged."""

        from pydantic_encryption.types import EncryptedValue
        from tests.unit.test_sqlalchemy.conftest import call_in_greenlet

        encrypted = call_in_greenlet(self.type_adapter.process_bind_param, "hello", None)
        double_encrypted = call_in_greenlet(
            self.type_adapter.process_bind_param, EncryptedValue(encrypted), None
        )

        assert encrypted == double_encrypted

    def test_process_literal_param_already_encrypted_returns_same(self):
        """Test that an already-encrypted value skipped by process_literal_param is returned unchanged."""

        from pydantic_encryption.types import EncryptedValue
        from tests.unit.test_sqlalchemy.conftest import call_in_greenlet

        encrypted = call_in_greenlet(self.type_adapter.process_literal_param, "hello", None)
        double_encrypted = call_in_greenlet(
            self.type_adapter.process_literal_param, EncryptedValue(encrypted), None
        )

        assert encrypted == double_encrypted
