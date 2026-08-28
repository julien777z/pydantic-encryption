import pytest

from pydantic_encryption.context import derive_column_context, encode_context


class TestDeriveColumnContext:
    """Test the rule that names the context an encrypted column binds its ciphertexts to."""

    def test_qualifies_a_column_with_its_schema(self):
        """Test that a column in a named schema binds to the schema-qualified table."""

        assert derive_column_context("users", "email", schema="secure") == b"secure.users.email"

    def test_omits_a_schema_that_is_absent(self):
        """Test that a column in an unqualified table binds to the table name alone."""

        assert derive_column_context("users", "email") == b"users.email"
        assert derive_column_context("users", "email", schema=None) == b"users.email"

    def test_two_schemas_separate_same_named_columns(self):
        """Test that one table name in two schemas does not produce one shared context."""

        first = derive_column_context("user_audit_log", "field_value_before", schema="secure")
        second = derive_column_context("user_audit_log", "field_value_before", schema="vaultgig")

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
