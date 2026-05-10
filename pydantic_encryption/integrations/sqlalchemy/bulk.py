import asyncio
from collections.abc import Iterable
from typing import Any

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
)
from pydantic_encryption.integrations.sqlalchemy.serialization import (
    decode_value,
)
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    read_raw_cell,
    set_decrypted,
)
from pydantic_encryption.types import EncryptedValue


def _column_key(column: InstrumentedAttribute | str) -> str:
    """Return the column key for an InstrumentedAttribute or string column name."""

    return column if isinstance(column, str) else column.key


def _resolve_backend() -> Any:
    """Return the configured encryption backend, raising if ENCRYPTION_METHOD is unset."""

    method = settings.ENCRYPTION_METHOD
    if method is None:
        raise ValueError("ENCRYPTION_METHOD must be set to decrypt values.")

    return get_encryption_backend(method)


async def _decrypt_assignments(
    backend: Any, assignments: list[tuple[Any, str, bytes]]
) -> None:
    """Decrypt every ``(row, key, ciphertext)`` triple in one ``asyncio.gather`` and write results back."""

    if not assignments:
        return

    plaintexts = await asyncio.gather(
        *(backend.async_decrypt(ciphertext) for _, _, ciphertext in assignments)
    )
    for (row, key, _), plaintext in zip(assignments, plaintexts):
        set_decrypted(row, key, decode_value(plaintext))


async def decrypt_rows(rows: Iterable[Any], *columns: InstrumentedAttribute | str) -> None:
    """Decrypt the given columns across every row in one ``asyncio.gather``."""

    if not columns:
        return

    backend = _resolve_backend()
    column_keys = [_column_key(c) for c in columns]
    assignments: list[tuple[Any, str, bytes]] = []
    for row in rows:
        for key in column_keys:
            value = read_raw_cell(row, key)
            if isinstance(value, EncryptedValue):
                assignments.append((row, key, bytes(value)))

    await _decrypt_assignments(backend, assignments)


def decrypt_rows_sync(rows: Iterable[Any], *columns: InstrumentedAttribute | str) -> None:
    """Sync decrypt fallback for descriptor reads outside an async-session greenlet."""

    if not columns:
        return

    backend = _resolve_backend()
    column_keys = [_column_key(c) for c in columns]
    for row in rows:
        for key in column_keys:
            value = read_raw_cell(row, key)
            if isinstance(value, EncryptedValue):
                set_decrypted(row, key, decode_value(backend.decrypt(bytes(value))))


async def decrypt_values(values: Iterable[Any]) -> list[Any]:
    """Decrypt a flat iterable of ciphertexts, preserving non-encrypted positions as-is."""

    values_list = list(values)
    if not values_list:
        return []

    backend = _resolve_backend()
    indexes: list[int] = []
    coros: list[Any] = []
    for index, value in enumerate(values_list):
        if isinstance(value, EncryptedValue):
            coros.append(backend.async_decrypt(bytes(value)))
            indexes.append(index)

    if not coros:
        return values_list

    plaintexts = await asyncio.gather(*coros)
    for index, plaintext in zip(indexes, plaintexts):
        values_list[index] = decode_value(plaintext)

    return values_list


def collect_encrypted_cells(
    entities: Any | Iterable[Any] | None,
    collected: dict[tuple[type, str], list[Any]],
    visited: set[int],
) -> None:
    """Group deferred-encrypted cells by ``(class, column)``, walking loaded relationships."""

    if entities is None:
        return

    if isinstance(entities, Iterable) and not isinstance(entities, (str, bytes, bytearray)):
        items = list(entities)
    else:
        items = [entities]

    for entity in items:
        if entity is None:
            continue

        entity_id = id(entity)
        if entity_id in visited:
            continue
        visited.add(entity_id)

        state = sa_inspect(entity, raiseerr=False)
        if state is None or not hasattr(state, "mapper"):
            continue

        for column in state.mapper.columns:
            if not isinstance(column.type, SQLAlchemyEncryptedValue):
                continue
            if not column.type._deferred:
                continue
            if isinstance(state.dict.get(column.key), EncryptedValue):
                collected.setdefault((type(entity), column.key), []).append(entity)

        unloaded = state.unloaded
        for relationship in state.mapper.relationships:
            if relationship.key in unloaded:
                continue
            related = state.dict.get(relationship.key)
            if related is None:
                continue
            if relationship.uselist:
                collect_encrypted_cells(list(related), collected, visited)
            else:
                collect_encrypted_cells(related, collected, visited)


async def bulk_decrypt_entities(entities: Any | Iterable[Any] | None) -> None:
    """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

    collected: dict[tuple[type, str], list[Any]] = {}
    collect_encrypted_cells(entities, collected, set())
    if not collected:
        return

    backend = _resolve_backend()
    assignments: list[tuple[Any, str, bytes]] = []
    for (_, column_key), rows in collected.items():
        for row in rows:
            value = read_raw_cell(row, column_key)
            if isinstance(value, EncryptedValue):
                assignments.append((row, column_key, bytes(value)))

    await _decrypt_assignments(backend, assignments)


async def decrypt_pending_fields(session: AsyncSession) -> None:
    """Force-decrypt every encrypted column on every instance bucketed in this session."""

    pending = session.info.pop(PENDING_DECRYPT_KEY, None)
    if not pending:
        return

    await bulk_decrypt_entities([row for rows in pending.values() for row in rows])


async def finalize_sqlalchemy_session(session: AsyncSession) -> None:
    """Commit so the pooled DB connection is released, then decrypt pending encrypted fields.

    The pending-decrypt bucket is captured from ``session.info`` first, then the open
    transaction is committed so the pooled DB connection is returned to the pool, and
    only then does the batched KMS decrypt run. This keeps the pool slot held for SQL
    work only -- the network-bound KMS round-trips no longer hold a connection -- which
    matters under concurrent read load where decrypt time dominates request duration.
    """

    pending = session.info.pop(PENDING_DECRYPT_KEY, None)

    if session.in_transaction():
        await session.commit()

    if pending:
        await bulk_decrypt_entities([row for rows in pending.values() for row in rows])


__all__ = [
    "bulk_decrypt_entities",
    "collect_encrypted_cells",
    "decrypt_pending_fields",
    "decrypt_rows",
    "decrypt_rows_sync",
    "decrypt_values",
    "finalize_sqlalchemy_session",
]
