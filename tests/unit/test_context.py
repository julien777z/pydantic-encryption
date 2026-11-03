from collections.abc import Callable

import pytest

from pydantic_encryption.context import (
    derive_column_context,
    derive_declared_context,
    derive_field_context,
    derive_row_context,
)


class TestContext:
    """Test the rules naming the context a column, a row's cell, a model field or a declared name binds to."""

    @pytest.mark.parametrize(
        ("derive", "args", "kwargs", "expected"),
        [
            (derive_column_context, ("records", "secret"), {}, b"records.secret"),
            (derive_column_context, ("records", "secret"), {"schema": None}, b"records.secret"),
            (derive_column_context, ("records", "secret"), {"schema": "left"}, b"left.records.secret"),
            (derive_row_context, ("records", "secret", "42"), {"schema": "left"}, b"left.records.secret.42"),
            (derive_field_context, ("app", "Record", "secret"), {}, b"\\field.app.Record.secret"),
            (derive_declared_context, ("records.draft",), {}, b"\\declared.records\\.draft"),
            (derive_declared_context, (b"records.draft",), {}, b"\\declared.records\\.draft"),
        ],
        ids=["column", "column-no-schema", "column-schema", "row", "field", "declared", "declared-bytes"],
    )
    def test_derived_context(
        self,
        derive: Callable[..., bytes],
        args: tuple[str | bytes, ...],
        kwargs: dict[str, str | None],
        expected: bytes,
    ):
        """Test that each location derives exactly the context its documented rule names."""

        assert derive(*args, **kwargs) == expected

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (
                derive_column_context("entries", "note", schema="left"),
                derive_column_context("entries", "note", schema="right"),
            ),
            (
                derive_row_context("records", "secret", "1", schema="app"),
                derive_row_context("records", "secret", "2", schema="app"),
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
                derive_field_context("left", "Record", "secret"),
                derive_column_context("Record", "secret", schema="left"),
            ),
            (
                derive_field_context("records", "secret", "42"),
                derive_row_context("records", "secret", "42", schema="app"),
            ),
            (
                derive_column_context("secret", "42", schema="records"),
                derive_row_context("records", "secret", "42", schema="app"),
            ),
            (
                derive_row_context("secret", "42", "7", schema="records"),
                derive_row_context("records", "secret", "42", "7", schema="app"),
            ),
            (derive_declared_context("records.draft"), derive_column_context("records", "draft")),
            (
                derive_declared_context("\\field.app.Record.secret"),
                derive_field_context("app", "Record", "secret"),
            ),
            (
                derive_declared_context("x.1"),
                derive_declared_context("x") + b".1",
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
            "declared-column",
            "declared-field",
            "declared-row",
        ],
    )
    def test_distinct_locations_differ(self, left: bytes, right: bytes):
        """Test that two distinct locations never derive one shared context."""

        assert left != right

    def test_row_context_requires_row_key(self):
        """Test that extending a column context with no primary key raises rather than binding it."""

        with pytest.raises(ValueError, match="needs the primary key"):
            derive_row_context("records", "secret", schema="app")

    @pytest.mark.parametrize(
        ("kwargs", "error", "message"),
        [
            ({}, TypeError, "schema"),
            ({"schema": ""}, ValueError, "cannot be empty"),
        ],
        ids=["missing", "empty"],
    )
    def test_row_context_requires_schema(self, kwargs: dict[str, str], error: type[Exception], message: str):
        """Test that a row context without a schema raises rather than reading like another location's."""

        with pytest.raises(error, match=message):
            derive_row_context("records", "secret", "42", **kwargs)

    def test_column_context_refuses_empty_schema(self):
        """Test that a column context refuses an empty schema as a row context does, not dropping it."""

        with pytest.raises(ValueError, match="cannot be empty"):
            derive_column_context("records", "secret", schema="")
