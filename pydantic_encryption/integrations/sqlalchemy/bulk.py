import asyncio
from typing import Any, Iterable

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.orm.attributes import InstrumentedAttribute

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


def _column_name(column: InstrumentedAttribute | str) -> str:
    if isinstance(column, str):
        return column
    return column.key


async def async_decrypt_rows(
    rows: Iterable[Any],
    *columns: InstrumentedAttribute | str,
    concurrency: int | None = None,
) -> None:
    """Bulk-decrypt deferred encrypted columns across many rows in parallel.

    Each non-``None`` ``(row, column)`` cell becomes one ``async_decrypt`` task.
    All tasks run via a single ``asyncio.gather``. With ``concurrency=N`` the
    tasks are wrapped in a ``Semaphore(N)``; with ``None`` (default) there is
    no explicit limit — the backend's connection pool is the effective bound.

    Columns may be passed as SQLAlchemy ``InstrumentedAttribute`` (e.g.
    ``User.email``) or plain strings (``"email"``). Decrypted values are
    ``setattr`` onto each row in-place; the row's SQLAlchemy state is not
    otherwise touched.
    """

    if not columns:
        return
    rows = list(rows)
    if not rows:
        return

    if settings.ENCRYPTION_METHOD is None:
        raise ValueError("ENCRYPTION_METHOD must be set to use async_decrypt_rows.")

    backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
    # Reuse a TypeDecorator instance purely for its deserialization helper.
    type_helper = SQLAlchemyEncryptedValue()
    column_names = [_column_name(c) for c in columns]

    semaphore = asyncio.Semaphore(concurrency) if concurrency is not None else None

    async def decrypt_cell(ciphertext: bytes) -> Any:
        if semaphore is not None:
            async with semaphore:
                plaintext = await backend.async_decrypt(ciphertext)
        else:
            plaintext = await backend.async_decrypt(ciphertext)
        return type_helper._deserialize_value(plaintext)

    assignments: list[tuple[Any, str]] = []
    coros = []
    for row in rows:
        for name in column_names:
            value = getattr(row, name, None)
            if value is None:
                continue
            ciphertext = bytes(value) if not isinstance(value, bytes) else value
            coros.append(decrypt_cell(ciphertext))
            assignments.append((row, name))

    if not coros:
        return

    results = await asyncio.gather(*coros)
    for (row, name), plaintext in zip(assignments, results):
        setattr(row, name, plaintext)


__all__ = ["async_decrypt_rows"]
