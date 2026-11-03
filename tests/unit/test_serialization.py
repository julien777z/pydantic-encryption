from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

import pytest

from pydantic_encryption.serialization import EncryptableValue, TypePrefix, decode_value, encode_value


class TestSerialization:
    """Test the ``version:type:data`` strings values encode to and decode from."""

    @pytest.mark.parametrize(
        ("value", "encoded"),
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
                datetime(2025, 1, 21, 14, 30, 45, tzinfo=UTC),
                f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00",
            ),
            (time(14, 30, 45), f"v1:{TypePrefix.TIME}:14:30:45"),
            (time(14, 30, 45, 123456), f"v1:{TypePrefix.TIME}:14:30:45.123456"),
            (time(14, 30, 45, tzinfo=UTC), f"v1:{TypePrefix.TIME}:14:30:45+00:00"),
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
    def test_value_encodes_and_decodes(self, value: EncryptableValue, encoded: str):
        """Test that a value encodes to its versioned string and decodes back to the same type."""

        decoded = decode_value(encoded)

        assert encode_value(value) == encoded
        assert decoded == value
        assert type(decoded) is type(value)

    @pytest.mark.parametrize(
        "value", [None, ["secret data"], {"secret": "data"}], ids=["none", "list", "dict"]
    )
    def test_unsupported_type_refused(self, value: object):
        """Test that encoding a value of a type no encrypted cell can hold raises with its type name."""

        with pytest.raises(TypeError, match=repr(type(value).__name__)):
            encode_value(value)

    @pytest.mark.parametrize("encoded", ["", ":secret data"], ids=["empty", "empty-version"])
    def test_versionless_string_decodes_to_itself(self, encoded: str):
        """Test that a string with nothing before its first separator is returned unchanged."""

        assert decode_value(encoded) == encoded

    @pytest.mark.parametrize(
        "encoded",
        ["v99:str:secret data", "v2:str:hello world", "str:hello world", "no_colon_here"],
        ids=["future-version", "next-version", "unversioned-type-prefix", "no-separator"],
    )
    def test_unknown_version_refused(self, encoded: str):
        """Test that a version this build does not write raises rather than guessing."""

        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value(encoded)

    def test_unknown_type_decodes_as_written(self):
        """Test that a type prefix this build does not write comes back as the data it carried."""

        assert decode_value("v1:mystery:secret data") == "secret data"
