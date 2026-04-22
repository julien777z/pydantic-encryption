import asyncio
from collections.abc import Awaitable, Iterable
from typing import Any

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    read_raw_cell,
    set_decrypted,
)
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.serialization import EncryptableValue, decode_value
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


def _resolve_concurrency(concurrency: int | None) -> int | None:
    """Pick the effective concurrency cap, falling back to settings.DECRYPT_CONCURRENCY when unset."""

    if concurrency is not None:
        return concurrency

    default = settings.DECRYPT_CONCURRENCY
    return default if default and default > 0 else None


async def _decrypt_cell(backend: Any, ciphertext: bytes) -> EncryptableValue:
    """Decrypt a single ciphertext and decode it to its original Python type."""

    plaintext = await backend.decrypt(ciphertext)

    return decode_value(plaintext)


async def _gather_with_limit(
    coros: list[Awaitable[Any]], concurrency: int | None
) -> list[Any]:
    """Gather coroutines with an optional semaphore-bounded concurrency cap."""

    if concurrency is None or concurrency <= 0:
        return await asyncio.gather(*coros)

    semaphore = asyncio.Semaphore(concurrency)

    async def guarded(coro: Awaitable[Any]) -> Any:
        async with semaphore:
            return await coro

    return await asyncio.gather(*(guarded(c) for c in coros))


async def decrypt_rows(
    rows: Iterable[Any],
    *columns: InstrumentedAttribute | str,
    concurrency: int | None = None,
) -> None:
    """Decrypt the given columns across every row in one asyncio.gather."""

    if not columns:
        return

    rows_list = list(rows)
    if not rows_list:
        return

    backend = _resolve_backend()
    column_keys = [_column_key(c) for c in columns]
    effective_concurrency = _resolve_concurrency(concurrency)

    assignments: list[tuple[Any, str]] = []
    coros: list[Awaitable[Any]] = []
    for row in rows_list:
        for key in column_keys:
            value = read_raw_cell(row, key)
            if not isinstance(value, EncryptedValue):
                continue
            coros.append(_decrypt_cell(backend, bytes(value)))
            assignments.append((row, key))

    if not coros:
        return

    results = await _gather_with_limit(coros, effective_concurrency)
    for (row, key), plaintext in zip(assignments, results):
        set_decrypted(row, key, plaintext)


async def decrypt_values(
    values: Iterable[Any],
    *,
    concurrency: int | None = None,
) -> list[Any]:
    """Decrypt a flat iterable of ciphertexts, preserving non-encrypted positions as-is."""

    values_list = list(values)
    if not values_list:
        return []

    backend = _resolve_backend()
    effective_concurrency = _resolve_concurrency(concurrency)

    indexes: list[int] = []
    coros: list[Awaitable[Any]] = []
    for index, value in enumerate(values_list):
        if not isinstance(value, EncryptedValue):
            continue
        coros.append(_decrypt_cell(backend, bytes(value)))
        indexes.append(index)

    if not coros:
        return values_list

    results = await _gather_with_limit(coros, effective_concurrency)
    for index, plaintext in zip(indexes, results):
        values_list[index] = plaintext

    return values_list


def collect_encrypted_cells(
    entities: Any | Iterable[Any] | None,
    collected: dict[tuple[type, str], list[Any]],
    visited: set[int],
) -> None:
    """Group deferred-encrypted cells by (class, column), walking loaded relationships."""

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

        mapper = state.mapper

        for column in mapper.columns:
            if not isinstance(column.type, SQLAlchemyEncryptedValue):
                continue
            if not column.type._deferred:
                continue
            value = state.dict.get(column.key)
            if not isinstance(value, EncryptedValue):
                continue
            collected.setdefault((type(entity), column.key), []).append(entity)

        unloaded = state.unloaded
        for relationship in mapper.relationships:
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
    visited: set[int] = set()
    collect_encrypted_cells(entities, collected, visited)

    if not collected:
        return

    await asyncio.gather(
        *(
            decrypt_rows(rows, getattr(cls, column_key))
            for (cls, column_key), rows in collected.items()
        )
    )


async def decrypt_pending_fields(session: AsyncSession) -> None:
    """Force-decrypt every encrypted column on every instance bucketed in this session."""

    pending = session.info.pop(PENDING_DECRYPT_KEY, None)
    if not pending:
        return

    await bulk_decrypt_entities([row for rows in pending.values() for row in rows])


__all__ = [
    "bulk_decrypt_entities",
    "collect_encrypted_cells",
    "decrypt_pending_fields",
    "decrypt_rows",
    "decrypt_values",
]
