import pytest

from pydantic_encryption.serialization import decode_value


class TestDecodeUnversioned:
    """Test what decoding makes of a string that carries no version this build writes."""

    def test_empty_string_decodes_to_itself(self):
        """Test that a value with nothing before its first separator is returned unchanged."""

        assert decode_value("") == ""

    def test_leading_separator_decodes_to_itself(self):
        """Test that a string whose version is empty is returned unchanged."""

        assert decode_value(":secret data") == ":secret data"

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
