import pytest

from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)


class TestRowBoundDeclaration:
    """Test what a column type accepts when asked to bind each row."""

    def test_array_refuses_to_bind_a_row(self):
        """Test that an encrypted array refuses row binding rather than promising it."""

        with pytest.raises(ValueError, match="cannot bind its elements to a row"):
            SQLAlchemyPGEncryptedArray(row_bound=True)

    def test_row_binding_changes_the_statement_cache_key(self):
        """Test that a row-bound column cannot share a cache key with a column-bound one."""

        column_bound = SQLAlchemyEncryptedValue("users.secret")
        row_bound = SQLAlchemyEncryptedValue("users.secret", row_bound=True)

        assert column_bound._static_cache_key != row_bound._static_cache_key

    def test_bound_context_refuses_a_row_bound_column(self):
        """Test that asking a row-bound column for one context raises rather than binding the column."""

        with pytest.raises(ValueError, match="binds each row separately"):
            SQLAlchemyEncryptedValue("users.secret", row_bound=True).bound_context()
