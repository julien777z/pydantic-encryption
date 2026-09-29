import pytest
from sqlalchemy.engine import Dialect

from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.serialization import EncryptableValue


class TestArrayProcessing:
    """Test how an encrypted array binds and reads the lists it holds."""

    def setup_method(self):
        """Build the column type under test."""

        self.column_type = SQLAlchemyPGEncryptedArray("tests.encrypted_array.values")

    @pytest.mark.parametrize("value", [None, []], ids=["none", "empty"])
    def test_empty_values_bind_unchanged(
        self, value: list[EncryptableValue | None] | None, sqlite_dialect: Dialect
    ):
        """Test that None and an empty list bind as themselves."""

        assert self.column_type.process_bind_param(value, sqlite_dialect) == value

    @pytest.mark.parametrize("value", [None, [], [None, None]], ids=["none", "empty", "none-elements"])
    def test_empty_values_read_unchanged(self, value: list[bytes | None] | None, sqlite_dialect: Dialect):
        """Test that None, an empty list and empty elements read back as themselves."""

        assert self.column_type.process_result_value(value, sqlite_dialect) == value

    def test_elements_encrypt_through_value_type(self):
        """Test that each element is encrypted by an encrypted-value column type."""

        assert isinstance(self.column_type._element_type, SQLAlchemyEncryptedValue)

    def test_python_type_is_list(self):
        """Test that the column type reports list as its Python type."""

        assert self.column_type.python_type is list
