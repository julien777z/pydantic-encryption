from typing import Final

CONTEXT_SEPARATOR: Final[str] = "."
CONTEXT_ESCAPE: Final[str] = "\\"
FIELD_CONTEXT_TAG: Final[bytes] = f"{CONTEXT_ESCAPE}field".encode("utf-8")
DECLARED_CONTEXT_TAG: Final[bytes] = f"{CONTEXT_ESCAPE}declared".encode("utf-8")


def escape_context_segment(segment: str | bytes) -> bytes:
    """Return one segment with the separator escaped, so no two segment lists share a context."""

    encoded = segment.encode("utf-8") if isinstance(segment, str) else segment
    escape = CONTEXT_ESCAPE.encode("utf-8")
    separator = CONTEXT_SEPARATOR.encode("utf-8")

    return encoded.replace(escape, escape * 2).replace(separator, escape + separator)


def join_context_segments(*segments: str | bytes) -> bytes:
    """Return the context naming the location its segments identify."""

    return CONTEXT_SEPARATOR.encode("utf-8").join(escape_context_segment(segment) for segment in segments)


def derive_column_context(table_name: str, column_name: str, *, schema: str | None = None) -> bytes:
    """Return the context an encrypted column of this name binds its ciphertexts to."""

    if schema == "":
        raise ValueError("A schema naming a column's table cannot be empty; pass None where it names none.")

    if schema is not None:
        return join_context_segments(schema, table_name, column_name)

    return join_context_segments(table_name, column_name)


def append_row_key(column_context: bytes, *row_key: str) -> bytes:
    """Return a column's context extended to name the one row whose cell it binds."""

    if not row_key:
        raise ValueError("A row-bound cell needs the primary key naming its row.")

    return CONTEXT_SEPARATOR.encode("utf-8").join((column_context, join_context_segments(*row_key)))


def derive_row_context(table_name: str, column_name: str, *row_key: str, schema: str) -> bytes:
    """Return the context one row's cell in an encrypted column binds its ciphertext to."""

    if schema == "":
        raise ValueError("A schema naming a column's table cannot be empty; pass None where it names none.")

    if schema is None:
        raise ValueError(
            "A row-bound cell needs a schema naming its table, or its context could read the same as a "
            "column's or another row's in a table that names one."
        )

    return append_row_key(derive_column_context(table_name, column_name, schema=schema), *row_key)


def derive_field_context(module_name: str, qualified_name: str, field_name: str) -> bytes:
    """Return the context a model field binds its ciphertext to, led by an escape no escaped name produces."""

    return CONTEXT_SEPARATOR.encode("utf-8").join(
        (FIELD_CONTEXT_TAG, join_context_segments(module_name, qualified_name, field_name))
    )


def derive_declared_context(name: str | bytes) -> bytes:
    """Return the context a declared name binds to, led by an escape no derived context starts with."""

    return CONTEXT_SEPARATOR.encode("utf-8").join((DECLARED_CONTEXT_TAG, escape_context_segment(name)))
