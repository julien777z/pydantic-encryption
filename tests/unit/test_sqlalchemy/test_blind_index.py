import pytest
from sqlalchemy.engine import Dialect

from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class TestSQLAlchemyBlindIndexValue:
    """Test the blind index a column type computes for the values bound to it."""

    def setup_method(self):
        """Build the column types under test."""

        self.column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        self.digit_column_type = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, strip_non_digits=True
        )

    @pytest.mark.parametrize(
        ("flags", "message"),
        [
            (
                {"strip_non_characters": True, "strip_non_digits": True},
                "strip_non_characters and strip_non_digits cannot both be True",
            ),
            (
                {"normalize_to_lowercase": True, "normalize_to_uppercase": True},
                "normalize_to_lowercase and normalize_to_uppercase cannot both be True",
            ),
        ],
        ids=["strip", "case"],
    )
    def test_conflicting_flags_refused(self, flags: dict[str, bool], message: str):
        """Test that two normalization flags that contradict each other are refused."""

        with pytest.raises(ValueError, match=message):
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, **flags)

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_method_recorded(self, method: BlindIndexMethod):
        """Test that the column type records the method it was declared with."""

        assert SQLAlchemyBlindIndexValue(method).method == method

    def test_python_type_is_bytes(self):
        """Test that the column type reports bytes as its Python type."""

        assert SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).python_type is bytes

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_none_binds_none(self, method: BlindIndexMethod, sqlite_dialect: Dialect):
        """Test that binding None stores None."""

        assert SQLAlchemyBlindIndexValue(method).process_bind_param(None, sqlite_dialect) is None

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_index_is_deterministic_digest(self, method: BlindIndexMethod, sqlite_dialect: Dialect):
        """Test that a value, as text or UTF-8 bytes, binds to one 32-byte index no other value shares."""

        column_type = SQLAlchemyBlindIndexValue(method)
        index = column_type.process_bind_param("first@example.test", sqlite_dialect)

        assert isinstance(index, bytes)
        assert len(index) == 32
        assert column_type.process_bind_param("first@example.test", sqlite_dialect) == index
        assert column_type.process_bind_param(b"first@example.test", sqlite_dialect) == index
        assert column_type.process_bind_param("second@example.test", sqlite_dialect) != index

    def test_precomputed_index_passes_through(self, sqlite_dialect: Dialect):
        """Test that binding an existing blind index stores it unchanged."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        index = column_type.process_bind_param("sample@example.test", sqlite_dialect)

        assert index is not None
        assert column_type.process_bind_param(BlindIndexValue(index), sqlite_dialect) == index

    def test_methods_differ(self, sqlite_dialect: Dialect):
        """Test that the two methods bind one value to different indexes."""

        hmac_index = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_bind_param(
            "sample@example.test", sqlite_dialect
        )
        argon2_index = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2).process_bind_param(
            "sample@example.test", sqlite_dialect
        )

        assert hmac_index != argon2_index

    def test_keys_differ(self, monkeypatch: pytest.MonkeyPatch, sqlite_dialect: Dialect):
        """Test that one value binds to different indexes under different secret keys."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "key-one")
        first = column_type.process_bind_param("sample@example.test", sqlite_dialect)

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "key-two")
        second = column_type.process_bind_param("sample@example.test", sqlite_dialect)

        assert first != second

    def test_missing_secret_key_refused(self, monkeypatch: pytest.MonkeyPatch, sqlite_dialect: Dialect):
        """Test that binding without BLIND_INDEX_SECRET_KEY raises."""

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_bind_param(
                "sample", sqlite_dialect
            )

    def test_none_result_reads_none(self, sqlite_dialect: Dialect):
        """Test that a stored None reads back as None."""

        assert (
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_result_value(None, sqlite_dialect)
            is None
        )

    def test_result_reads_as_blind_index(self, sqlite_dialect: Dialect):
        """Test that a stored index reads back as a BlindIndexValue of the same bytes."""

        stored = b"\x01\x02\x03\x04" * 8
        result = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_result_value(
            stored, sqlite_dialect
        )

        assert isinstance(result, BlindIndexValue)
        assert result == stored

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

    def test_unnormalized_column_indexes_raw(self, sqlite_dialect: Dialect):
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

    def test_made_index_is_blind_index(self):
        """Test that the result is a 32-byte BlindIndexValue."""

        result = self.column_type.make_blind_index_value("sample@example.test")

        assert isinstance(result, BlindIndexValue)
        assert len(result) == 32

    def test_unsalted_matches_bind(self, sqlite_dialect: Dialect):
        """Test that an unsalted index equals the one the column binds."""

        made = self.column_type.make_blind_index_value("sample@example.test")
        bound = self.column_type.process_bind_param("sample@example.test", sqlite_dialect)

        assert bound is not None
        assert bytes(made) == bytes(bound)

    def test_salted_differs_from_unsalted(self):
        """Test that salting changes the index."""

        salted = self.column_type.make_blind_index_value("sample@example.test", salt=b"\x01" * 16)

        assert salted != self.column_type.make_blind_index_value("sample@example.test")

    def test_salts_differ(self):
        """Test that different salts give different indexes."""

        salted_a = self.column_type.make_blind_index_value("sample@example.test", salt=b"\x01" * 16)
        salted_b = self.column_type.make_blind_index_value("sample@example.test", salt=b"\x02" * 16)

        assert salted_a != salted_b

    def test_column_flags_applied(self):
        """Test that the column's normalization flags apply before salting."""

        salt = b"\x01" * 16

        assert self.digit_column_type.make_blind_index_value(
            "12-34", salt=salt
        ) == self.digit_column_type.make_blind_index_value("1234", salt=salt)

    def test_salted_index_passes_through_bind(self, sqlite_dialect: Dialect):
        """Test that a pre-salted index is stored unchanged by the column."""

        salted = self.column_type.make_blind_index_value("sample@example.test", salt=b"\x01" * 16)
        bound = self.column_type.process_bind_param(salted, sqlite_dialect)

        assert bound is not None
        assert bytes(bound) == bytes(salted)
