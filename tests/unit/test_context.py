from collections.abc import Callable

import pytest

from pydantic_encryption.context import derive_column_context, derive_field_context, derive_row_context


class TestContext:
    """Test the rules that name the context a column, a row's cell or a model field binds to."""

    @pytest.mark.parametrize(
        ("derive", "args", "kwargs", "expected"),
        [
            (derive_column_context, ("users", "email"), {}, b"users.email"),
            (derive_column_context, ("users", "email"), {"schema": None}, b"users.email"),
            (derive_column_context, ("users", "email"), {"schema": "archive"}, b"archive.users.email"),
            (derive_row_context, ("users", "email", "42"), {"schema": "archive"}, b"archive.users.email.42"),
            (derive_field_context, ("app", "Record", "secret"), {}, b"\\field.app.Record.secret"),
        ],
        ids=["column", "column-no-schema", "column-schema", "row", "field"],
    )
    def test_derived_context(
        self,
        derive: Callable[..., bytes],
        args: tuple[str, ...],
        kwargs: dict[str, str | None],
        expected: bytes,
    ):
        """Test that each location derives exactly the context its documented rule names."""

        assert derive(*args, **kwargs) == expected

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (
                derive_column_context("entries", "note", schema="archive"),
                derive_column_context("entries", "note", schema="public"),
            ),
            (
                derive_row_context("users", "email", "1", schema="app"),
                derive_row_context("users", "email", "2", schema="app"),
            ),
            (
                derive_field_context("app.models", "Record", "secret"),
                derive_field_context("app.models", "Record", "other_secret"),
            ),
            (derive_column_context("a.b", "c"), derive_column_context("b", "c", schema="a")),
            (
                derive_row_context("t", "col", "1.2", schema="app"),
                derive_row_context("t", "col.1", "2", schema="app"),
            ),
            (derive_field_context("a.b", "Model", "x"), derive_field_context("a", "b.Model", "x")),
            (
                derive_row_context("t", "c", "1,2", "3", schema="app"),
                derive_row_context("t", "c", "1", "2,3", schema="app"),
            ),
            (
                derive_field_context("billing", "Invoice", "total"),
                derive_column_context("Invoice", "total", schema="billing"),
            ),
            (
                derive_field_context("users", "email", "42"),
                derive_row_context("users", "email", "42", schema="app"),
            ),
            (
                derive_column_context("email", "42", schema="users"),
                derive_row_context("users", "email", "42", schema="app"),
            ),
            (
                derive_row_context("email", "42", "7", schema="users"),
                derive_row_context("users", "email", "42", "7", schema="app"),
            ),
        ],
        ids=[
            "schemas",
            "rows",
            "fields",
            "dotted-table",
            "dotted-row-key",
            "dotted-module",
            "composite-row-key",
            "field-column",
            "field-row",
            "column-row",
            "row-composite-row",
        ],
    )
    def test_distinct_locations_differ(self, left: bytes, right: bytes):
        """Test that two distinct locations never derive one shared context."""

        assert left != right

    def test_row_context_requires_row_key(self):
        """Test that extending a column context with no primary key raises rather than binding it."""

        with pytest.raises(ValueError, match="needs the primary key"):
            derive_row_context("users", "email", schema="app")

    @pytest.mark.parametrize(
        ("kwargs", "error", "message"),
        [
            ({}, TypeError, "schema"),
            ({"schema": ""}, ValueError, "needs a schema"),
        ],
        ids=["missing", "empty"],
    )
    def test_row_context_requires_schema(self, kwargs: dict[str, str], error: type[Exception], message: str):
        """Test that a row context without a schema raises rather than reading like a column's or another row's."""

        with pytest.raises(error, match=message):
            derive_row_context("users", "email", "42", **kwargs)
