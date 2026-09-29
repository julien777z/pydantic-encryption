import pytest
from sqlalchemy.engine import Dialect

from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod


class TestBlindIndexNormalization:
    """Test the normalization a blind index column applies before indexing."""

    @pytest.mark.parametrize(
        ("flags", "raw", "normalized"),
        [
            ({"strip_whitespace": True}, "  hello   world  ", "hello world"),
            ({"strip_non_characters": True}, "hello123world!", "helloworld"),
            ({"strip_trailing_punctuation": True}, "first second.", "first second"),
            ({"strip_non_digits": True}, "a1 (b2) c3-d4", "1234"),
            ({"normalize_to_lowercase": True}, "Hello@Example.COM", "hello@example.com"),
            ({"normalize_to_uppercase": True}, "Hello@Example.com", "HELLO@EXAMPLE.COM"),
            (
                {"strip_whitespace": True, "normalize_to_lowercase": True},
                "  Hello@Example.COM  ",
                "hello@example.com",
            ),
        ],
        ids=[
            "strip-whitespace",
            "strip-non-characters",
            "strip-trailing-punctuation",
            "strip-non-digits",
            "lowercase",
            "uppercase",
            "combined",
        ],
    )
    def test_raw_matches_normalized(
        self, flags: dict[str, bool], raw: str, normalized: str, sqlite_dialect: Dialect
    ):
        """Test that a raw value indexes the same as its normalized form."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, **flags)

        assert column_type.process_bind_param(raw, sqlite_dialect) == column_type.process_bind_param(
            normalized, sqlite_dialect
        )

    def test_unnormalized_column_keeps_raw(self, sqlite_dialect: Dialect):
        """Test that a column without flags indexes a raw value differently from its normalized form."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        assert column_type.process_bind_param(
            "  hello   world  ", sqlite_dialect
        ) != column_type.process_bind_param("hello world", sqlite_dialect)

    def test_bytes_not_normalized(self, sqlite_dialect: Dialect):
        """Test that bytes are indexed as given while text is normalized."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, normalize_to_lowercase=True)

        assert column_type.process_bind_param(b"HELLO", sqlite_dialect) != column_type.process_bind_param(
            "HELLO", sqlite_dialect
        )
