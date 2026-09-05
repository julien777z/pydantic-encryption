from datetime import date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID, uuid4

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
            Decimal("1.10"),
            uuid4(),
            date(2026, 1, 2),
            datetime(2026, 1, 2, 3, 4, 5),
            time(3, 4, 5),
            timedelta(days=1, seconds=2, microseconds=3),
        ],
        ids=[
            "str",
            "bytes",
            "true",
            "false",
            "int",
            "negative-int",
            "float",
            "decimal",
            "uuid",
            "date",
            "datetime",
            "time",
            "timedelta",
        ],
    )
    def test_a_value_decodes_to_what_it_encoded(self, value: EncryptableValue):
        """Test that decoding an encoded value returns the same value and type."""

        decoded = decode_value(encode_value(value))

        assert decoded == value
        assert type(decoded) is type(value)


class TestDecodeUnversioned:
    """Test what decoding makes of a string that carries no version."""

    def test_an_empty_string_decodes_to_itself(self):
        """Test that a value with nothing before its first separator is returned unchanged."""

        assert decode_value("") == ""

    def test_a_leading_separator_decodes_to_itself(self):
        """Test that a string whose version is empty is returned unchanged."""

        assert decode_value(":secret data") == ":secret data"

    def test_an_unknown_version_is_refused(self):
        """Test that a version this build does not write raises rather than guessing."""

        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("v99:str:secret data")

    def test_an_unknown_type_decodes_as_written(self):
        """Test that a type prefix this build does not write comes back as the data it carried."""

        assert decode_value("v1:mystery:secret data") == "secret data"
