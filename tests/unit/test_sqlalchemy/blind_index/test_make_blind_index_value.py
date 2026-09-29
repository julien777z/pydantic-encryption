from sqlalchemy.engine import Dialect
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class TestMakeBlindIndexValue:
    """Test the salted blind index a column type builds for its own method and flags."""

    def setup_method(self):
        """Build the column types under test."""

        self.column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        self.digit_column_type = SQLAlchemyBlindIndexValue(
            BlindIndexMethod.HMAC_SHA256, strip_non_digits=True
        )

    def test_returns_blind_index(self):
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
