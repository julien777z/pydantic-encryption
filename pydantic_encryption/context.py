def encode_context(context: str | bytes | None) -> bytes | None:
    """Return UTF-8 bytes for a declared context, or ``None`` when one is to be derived."""

    return context.encode("utf-8") if isinstance(context, str) else context


def derive_column_context(table_name: str, column_name: str, *, schema: str | None = None) -> bytes:
    """Return the context an encrypted column of this name binds its ciphertexts to."""

    qualified_table = f"{schema}.{table_name}" if schema else table_name

    return f"{qualified_table}.{column_name}".encode("utf-8")


def derive_row_context(
    table_name: str, column_name: str, row_key: str, *, schema: str | None = None
) -> bytes:
    """Return the context one row's cell in an encrypted column binds its ciphertext to."""

    column_context = derive_column_context(table_name, column_name, schema=schema)

    return b".".join((column_context, row_key.encode("utf-8")))
