from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import UUID

import pytest

from pydantic_encryption.serialization import TypePrefix, encode_value


class TestEncodeValue:
    """Test the ``version:type:data`` string each supported value encodes to."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("hello world", f"v1:{TypePrefix.STR}:hello world"),
            ("hello:world", f"v1:{TypePrefix.STR}:hello:world"),
            (
                b"\x00\x01\x02\x03binary\xff\xfe",
                f"v1:{TypePrefix.BYTES}:AAECA2JpbmFyef/+",
            ),
            (b"", f"v1:{TypePrefix.BYTES}:"),
            (42, f"v1:{TypePrefix.INT}:42"),
            (-123, f"v1:{TypePrefix.INT}:-123"),
            (True, f"v1:{TypePrefix.BOOL}:true"),
            (False, f"v1:{TypePrefix.BOOL}:false"),
            (date(2025, 1, 21), f"v1:{TypePrefix.DATE}:2025-01-21"),
            (datetime(2025, 1, 21, 14, 30, 45), f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45"),
            (
                datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc),
                f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00",
            ),
            (time(14, 30, 45), f"v1:{TypePrefix.TIME}:14:30:45"),
            (time(14, 30, 45, 123456), f"v1:{TypePrefix.TIME}:14:30:45.123456"),
            (time(14, 30, 45, tzinfo=timezone.utc), f"v1:{TypePrefix.TIME}:14:30:45+00:00"),
            (timedelta(days=1, hours=2, minutes=30, seconds=45), f"v1:{TypePrefix.TIMEDELTA}:1,9045,0"),
            (timedelta(days=-1, hours=-2), f"v1:{TypePrefix.TIMEDELTA}:-2,79200,0"),
            (timedelta(seconds=1.5), f"v1:{TypePrefix.TIMEDELTA}:0,1,500000"),
            (3.14159, f"v1:{TypePrefix.FLOAT}:3.14159"),
            (-2.5, f"v1:{TypePrefix.FLOAT}:-2.5"),
            (1e-10, f"v1:{TypePrefix.FLOAT}:1e-10"),
            (Decimal("123.456789"), f"v1:{TypePrefix.DECIMAL}:123.456789"),
            (
                Decimal("0.123456789012345678901234567890"),
                f"v1:{TypePrefix.DECIMAL}:0.123456789012345678901234567890",
            ),
            (Decimal("-999.99"), f"v1:{TypePrefix.DECIMAL}:-999.99"),
            (
                UUID("12345678-1234-5678-1234-567812345678"),
                f"v1:{TypePrefix.UUID}:12345678-1234-5678-1234-567812345678",
            ),
        ],
        ids=[
            "str",
            "str-with-colon",
            "bytes",
            "bytes-empty",
            "int",
            "int-negative",
            "bool-true",
            "bool-false",
            "date",
            "datetime",
            "datetime-with-timezone",
            "time",
            "time-with-microseconds",
            "time-with-timezone",
            "timedelta",
            "timedelta-negative",
            "timedelta-fractional",
            "float",
            "float-negative",
            "float-scientific",
            "decimal",
            "decimal-high-precision",
            "decimal-negative",
            "uuid",
        ],
    )
    def test_wire_format(self, value: object, expected: str):
        """Test that a supported value encodes to its versioned, type-prefixed string."""

        assert encode_value(value) == expected
