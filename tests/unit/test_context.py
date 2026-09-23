import pytest

from pydantic_encryption.context import (
    derive_column_context,
    derive_field_context,
    derive_row_context,
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

        assert derive_field_context("app", "Record", "secret") == b"app.Record.secret"

    def test_two_fields_of_one_model_bind_separately(self):
        """Test that sibling fields of one model do not share a context."""

        first = derive_field_context("app.models", "Record", "secret")
        second = derive_field_context("app.models", "Record", "other_secret")

        assert first != second


class TestContextSegmentEscaping:
    """Test that no two distinct locations can share one derived context."""

    def test_a_dotted_table_does_not_collide_with_a_schema(self):
        """Test that a table whose name holds a separator binds apart from a qualified table."""

        assert derive_column_context("a.b", "c") != derive_column_context("b", "c", schema="a")

    def test_a_dotted_row_key_does_not_collide_with_a_dotted_column(self):
        """Test that a separator inside a row key stays inside that row key."""

        assert derive_row_context("t", "col", "1.2") != derive_row_context("t", "col.1", "2")

    def test_a_dotted_module_does_not_collide_with_a_nested_class(self):
        """Test that a class nested in another binds apart from one in a submodule."""

        assert derive_field_context("a.b", "Model", "x") != derive_field_context("a", "b.Model", "x")

    def test_composite_row_keys_do_not_collide_across_component_boundaries(self):
        """Test that two primary keys splitting the same characters differently bind apart."""

        assert derive_row_context("t", "c", "1,2", "3") != derive_row_context("t", "c", "1", "2,3")

    def test_a_row_context_needs_a_row_to_name(self):
        """Test that extending a column context with no primary key raises rather than binding it."""

        with pytest.raises(ValueError, match="needs the primary key"):
            derive_row_context("users", "email")

    def test_an_ordinary_name_carries_no_escape(self):
        """Test that a name without a separator reads exactly as it is written."""

        assert derive_column_context("users", "email") == b"users.email"
