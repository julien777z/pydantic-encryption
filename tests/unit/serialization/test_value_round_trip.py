from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from pydantic_encryption.serialization import EncryptableValue, decode_value, encode_value


class TestValueRoundTrip:
    """Test that a value comes back as the type it went in as."""

    @pytest.mark.parametrize(
        "value",
        [
            "secret data",
            b"\x00\x01\xff",
            True,
            False,
            42,
            -7,
            3.5,
            3.141592653589793,
            Decimal("1.10"),
            Decimal("123.456789012345678901234567890"),
            uuid4(),
            date(2026, 1, 2),
            datetime(2026, 1, 2, 3, 4, 5),
            datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc),
            time(3, 4, 5),
            time(14, 30, 45, 123456, tzinfo=timezone.utc),
            timedelta(days=1, seconds=2, microseconds=3),
            timedelta(days=-10, hours=-5),
        ],
        ids=[
            "str",
            "bytes",
            "true",
            "false",
            "int",
            "negative-int",
            "float",
            "float-full-precision",
            "decimal",
            "decimal-high-precision",
            "uuid",
            "date",
            "datetime",
            "datetime-with-timezone",
            "time",
            "time-with-timezone",
            "timedelta",
            "timedelta-negative",
        ],
    )
    def test_decodes_to_encoded_value(self, value: EncryptableValue):
        """Test that decoding an encoded value returns the same value and type."""

        decoded = decode_value(encode_value(value))

        assert decoded == value
        assert type(decoded) is type(value)
