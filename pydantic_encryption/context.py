def encode_context(context: str | bytes | None) -> bytes | None:
    """Return UTF-8 bytes for a declared context, or ``None`` when one is to be derived."""

    return context.encode("utf-8") if isinstance(context, str) else context


def derive_column_context(table_name: str, column_name: str, *, schema: str | None = None) -> bytes:
    """Return the context an encrypted column of this name binds its ciphertexts to."""

    qualified_table = f"{schema}.{table_name}" if schema else table_name

    return f"{qualified_table}.{column_name}".encode("utf-8")


def append_row_key(column_context: bytes, row_key: str) -> bytes:
    """Return a column's context extended to name the one row whose cell it binds."""

    return b".".join((column_context, row_key.encode("utf-8")))


def derive_row_context(
    table_name: str, column_name: str, row_key: str, *, schema: str | None = None
) -> bytes:
    """Return the context one row's cell in an encrypted column binds its ciphertext to."""

    return append_row_key(derive_column_context(table_name, column_name, schema=schema), row_key)


def derive_field_context(module_name: str, qualified_name: str, field_name: str) -> bytes:
    """Return the context an encrypted model field binds its ciphertext to."""

    return f"{module_name}.{qualified_name}.{field_name}".encode("utf-8")
