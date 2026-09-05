import pytest

from pydantic_encryption.context import (
    derive_column_context,
    derive_field_context,
    derive_row_context,
    encode_context,
)


class TestDeriveColumnContext:
    """Test the rule that names the context an encrypted column binds its ciphertexts to."""

    def test_qualifies_a_column_with_its_schema(self):
        """Test that a column in a named schema binds to the schema-qualified table."""

        assert derive_column_context("users", "email", schema="archive") == b"archive.users.email"

    def test_omits_a_schema_that_is_absent(self):
        """Test that a column in an unqualified table binds to the table name alone."""

        assert derive_column_context("users", "email") == b"users.email"
        assert derive_column_context("users", "email", schema=None) == b"users.email"

    def test_two_schemas_separate_same_named_columns(self):
        """Test that one table name in two schemas does not produce one shared context."""

        first = derive_column_context("entries", "note", schema="archive")
        second = derive_column_context("entries", "note", schema="public")

        assert first != second


class TestDeriveRowContext:
    """Test the rule that names the context one row's cell binds its ciphertext to."""

    def test_extends_the_column_context_with_the_row(self):
        """Test that a cell's context is its column's context followed by the row it belongs to."""

        assert derive_row_context("users", "email", "42") == b"users.email.42"

    def test_qualifies_a_row_with_its_schema(self):
        """Test that a schema-qualified column carries through to its rows."""

        assert derive_row_context("users", "email", "42", schema="archive") == b"archive.users.email.42"

    def test_two_rows_of_one_column_bind_separately(self):
        """Test that two rows of the same column do not share a context."""

        assert derive_row_context("users", "email", "1") != derive_row_context("users", "email", "2")


class TestDeriveFieldContext:
    """Test the rule that names the context an encrypted model field binds its ciphertext to."""

    def test_names_the_module_class_and_field(self):
        """Test that a field's context spells out where the field is declared."""

        assert derive_field_context("app.models", "Record", "secret") == b"app.models.Record.secret"

    def test_two_fields_of_one_model_bind_separately(self):
        """Test that sibling fields of one model do not share a context."""

        first = derive_field_context("app.models", "Record", "secret")
        second = derive_field_context("app.models", "Record", "other_secret")

        assert first != second


class TestEncodeContext:
    """Test the coercion applied to a declared context."""

    @pytest.mark.parametrize(
        "context, expected",
        [("users.email", b"users.email"), (b"users.email", b"users.email"), (None, None)],
        ids=["str", "bytes", "absent"],
    )
    def test_encodes_a_declared_context(self, context: str | bytes | None, expected: bytes | None):
        """Test that a declared context becomes bytes and an absent one stays absent."""

        assert encode_context(context) == expected
