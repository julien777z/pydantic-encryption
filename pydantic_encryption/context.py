from typing import Final

CONTEXT_SEPARATOR: Final[str] = "."
CONTEXT_ESCAPE: Final[str] = "\\"


def escape_context_segment(segment: str) -> str:
    """Return one segment with the separator escaped, so no two segment lists share a context."""

    return segment.replace(CONTEXT_ESCAPE, CONTEXT_ESCAPE * 2).replace(
        CONTEXT_SEPARATOR, CONTEXT_ESCAPE + CONTEXT_SEPARATOR
    )


def join_context_segments(*segments: str) -> bytes:
    """Return the context naming the location its segments identify."""

    return CONTEXT_SEPARATOR.join(escape_context_segment(segment) for segment in segments).encode("utf-8")


def derive_column_context(table_name: str, column_name: str, *, schema: str | None = None) -> bytes:
    """Return the context an encrypted column of this name binds its ciphertexts to."""

    if schema:
        return join_context_segments(schema, table_name, column_name)

    return join_context_segments(table_name, column_name)


def append_row_key(column_context: bytes, *row_key: str) -> bytes:
    """Return a column's context extended to name the one row whose cell it binds."""

    if not row_key:
        raise ValueError("A row-bound cell needs the primary key naming its row.")

    return CONTEXT_SEPARATOR.encode("utf-8").join((column_context, join_context_segments(*row_key)))


def derive_row_context(table_name: str, column_name: str, *row_key: str, schema: str | None = None) -> bytes:
    """Return the context one row's cell in an encrypted column binds its ciphertext to."""

    return append_row_key(derive_column_context(table_name, column_name, schema=schema), *row_key)


def derive_field_context(module_name: str, qualified_name: str, field_name: str) -> bytes:
    """Return the context an encrypted model field binds its ciphertext to."""

    return join_context_segments(module_name, qualified_name, field_name)
