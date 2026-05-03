import asyncio
from collections.abc import Iterable
from typing import Any

from pydantic import ConfigDict, Field, validate_call

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
    EncryptableValue,
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


def _resolve_chunk_count(concurrency: int | None) -> int:
    """Return the number of parallel chunks to split a decrypt batch into."""

    if concurrency is None:
        concurrency = settings.DECRYPT_CONCURRENCY

    return max(1, concurrency)


def _split_into_chunks(items: list[bytes], chunk_count: int) -> list[list[bytes]]:
    """Split items into ``chunk_count`` near-equal chunks; capped at ``len(items)``."""

    chunk_count = min(chunk_count, len(items))
    base, extra = divmod(len(items), chunk_count)

    chunks: list[list[bytes]] = []
    start = 0
    for index in range(chunk_count):
        size = base + (1 if index < extra else 0)
        chunks.append(items[start:start + size])
        start += size

    return chunks


def _decrypt_chunk_sync(backend: Any, ciphertexts: list[bytes]) -> list[EncryptableValue]:
    """Decrypt a chunk of ciphertexts sequentially in one thread."""

    return [decode_value(backend.decrypt(ciphertext)) for ciphertext in ciphertexts]


async def _decrypt_ciphertexts_chunked(
    backend: Any,
    ciphertexts: list[bytes],
    concurrency: int | None,
) -> list[EncryptableValue]:
    """Decrypt many ciphertexts via N parallel thread workers, each running its chunk serially.

    One ``asyncio.to_thread`` dispatch per chunk replaces one dispatch per cell, which removes
    the per-cell scheduler/thread-pool overhead that dominates wall-clock under bulk loads.
    """

    if not ciphertexts:
        return []

    chunks = _split_into_chunks(ciphertexts, _resolve_chunk_count(concurrency))
    chunk_results = await asyncio.gather(
        *(asyncio.to_thread(_decrypt_chunk_sync, backend, chunk) for chunk in chunks)
    )

    return [value for chunk_result in chunk_results for value in chunk_result]


@validate_call(config=ConfigDict(arbitrary_types_allowed=True))
async def decrypt_rows(
    rows: Iterable[Any],
    *columns: InstrumentedAttribute | str,
    concurrency: int | None = Field(default=None, gt=0),
) -> None:
    """Decrypt the given columns across every row using chunked thread workers."""

    if not columns:
        return

    rows_list = list(rows)
    if not rows_list:
        return

    backend = _resolve_backend()
    column_keys = [_column_key(c) for c in columns]

    assignments: list[tuple[Any, str]] = []
    ciphertexts: list[bytes] = []
    for row in rows_list:
        for key in column_keys:
            value = read_raw_cell(row, key)
            if not isinstance(value, EncryptedValue):
                continue
            ciphertexts.append(bytes(value))
            assignments.append((row, key))

    if not ciphertexts:
        return

    plaintexts = await _decrypt_ciphertexts_chunked(backend, ciphertexts, concurrency)
    for (row, key), plaintext in zip(assignments, plaintexts):
        set_decrypted(row, key, plaintext)


def decrypt_rows_sync(
    rows: Iterable[Any], *columns: InstrumentedAttribute | str
) -> None:
    """Sync decrypt fallback for descriptor reads outside an async-session greenlet."""

    if not columns:
        return

    rows_list = list(rows)
    if not rows_list:
        return

    backend = _resolve_backend()
    column_keys = [_column_key(c) for c in columns]

    for row in rows_list:
        for key in column_keys:
            value = read_raw_cell(row, key)
            if not isinstance(value, EncryptedValue):
                continue
            plaintext = decode_value(backend.decrypt(bytes(value)))
            set_decrypted(row, key, plaintext)


@validate_call(config=ConfigDict(arbitrary_types_allowed=True))
async def decrypt_values(
    values: Iterable[Any],
    *,
    concurrency: int | None = Field(default=None, gt=0),
) -> list[Any]:
    """Decrypt a flat iterable of ciphertexts, preserving non-encrypted positions as-is."""

    values_list = list(values)
    if not values_list:
        return []

    backend = _resolve_backend()

    indexes: list[int] = []
    ciphertexts: list[bytes] = []
    for index, value in enumerate(values_list):
        if not isinstance(value, EncryptedValue):
            continue
        ciphertexts.append(bytes(value))
        indexes.append(index)

    if not ciphertexts:
        return values_list

    plaintexts = await _decrypt_ciphertexts_chunked(backend, ciphertexts, concurrency)
    for index, plaintext in zip(indexes, plaintexts):
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


async def finalize_sqlalchemy_session(session: AsyncSession) -> None:
    """Decrypt every pending encrypted field, then commit so the connection is released.

    Descriptor-driven decryption runs through SQLAlchemy's greenlet bridge, which keeps
    the current pooled connection checked out while each KMS round-trip is in flight. On
    read endpoints that build a response body after querying, that can hold a connection
    open for hundreds of milliseconds per request. Call this at the end of a service
    function, after all DB work is done, to drain the pending bucket inside one batched
    ``asyncio.gather`` and commit the transaction so the pool slot is returned before the
    caller serializes its response.
    """

    await decrypt_pending_fields(session)

    if session.in_transaction():
        await session.commit()


__all__ = [
    "bulk_decrypt_entities",
    "collect_encrypted_cells",
    "decrypt_pending_fields",
    "decrypt_rows",
    "decrypt_rows_sync",
    "decrypt_values",
    "finalize_sqlalchemy_session",
]
