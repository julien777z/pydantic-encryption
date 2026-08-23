import asyncio
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from functools import cache
from typing import Any, Final, TypedDict

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.encryption import DeferrableEncryptedType
from pydantic_encryption.integrations.sqlalchemy.serialization import (
    decode_value,
)
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    read_raw_cell,
    set_decrypted,
)
from pydantic_encryption.types import EncryptedValue


class DecryptAssignment(TypedDict):
    """One encrypted cell, or one element of an encrypted array cell, awaiting decryption."""

    row: Any
    column_key: str
    element_index: int | None
    ciphertext: bytes


def cell_assignments(row: Any, column_key: str, value: Any) -> list[DecryptAssignment]:
    """Return one assignment per ciphertext a loaded cell still holds, array elements included."""

    if isinstance(value, EncryptedValue):
        return [
            DecryptAssignment(row=row, column_key=column_key, element_index=None, ciphertext=bytes(value))
        ]

    if not isinstance(value, list):
        return []

    return [
        DecryptAssignment(row=row, column_key=column_key, element_index=index, ciphertext=bytes(element))
        for index, element in enumerate(value)
        if isinstance(element, EncryptedValue)
    ]


#: Sized for KMS round trips rather than for cores, since a thread waiting on one releases the GIL.
CRYPTO_MAX_WORKERS: Final[int] = 64


@cache
def decryption_executor() -> ThreadPoolExecutor:
    """Return the process-wide pool that keeps decryption off the event loop."""

    return ThreadPoolExecutor(
        max_workers=CRYPTO_MAX_WORKERS,
        thread_name_prefix="pydantic-encryption-decrypt",
    )


def decrypt_batch(backend: Any, ciphertexts: list[bytes]) -> list[str]:
    """Decrypt a whole batch of ciphertexts on one worker thread."""

    return [backend.decrypt(ciphertext) for ciphertext in ciphertexts]


async def decrypt_off_loop(backend: Any, ciphertexts: list[bytes]) -> list[str]:
    """Decrypt a batch in one executor dispatch rather than one dispatch per value."""

    loop = asyncio.get_running_loop()

    return await loop.run_in_executor(decryption_executor(), decrypt_batch, backend, ciphertexts)


def column_key(column: InstrumentedAttribute | str) -> str:
    """Return the column key for an InstrumentedAttribute or string column name."""

    return column if isinstance(column, str) else column.key


def resolve_backend() -> Any:
    """Return the configured encryption backend, raising if ENCRYPTION_METHOD is unset."""

    method = settings.ENCRYPTION_METHOD
    if method is None:
        raise ValueError("ENCRYPTION_METHOD must be set to decrypt values.")

    return get_encryption_backend(method)


def collect_row_assignments(rows: Iterable[Any], column_keys: Iterable[str]) -> list[DecryptAssignment]:
    """Build one assignment per encrypted cell, and one per element of an encrypted array cell."""

    keys = list(column_keys)

    return [
        assignment
        for row in rows
        for key in keys
        for assignment in cell_assignments(row, key, read_raw_cell(row, key))
    ]


def apply_plaintexts(assignments: list[DecryptAssignment], plaintexts: list[str]) -> None:
    """Write a batch's decrypted values back onto the rows they came from."""

    arrays: dict[tuple[int, str], tuple[Any, list[Any]]] = {}

    for assignment, plaintext in zip(assignments, plaintexts):
        row = assignment["row"]
        column_key = assignment["column_key"]
        element_index = assignment["element_index"]
        value = decode_value(plaintext)

        if element_index is None:
            set_decrypted(row, column_key, value)

            continue

        _, elements = arrays.setdefault((id(row), column_key), (row, list(read_raw_cell(row, column_key))))
        elements[element_index] = value

    for (_, column_key), (row, elements) in arrays.items():
        set_decrypted(row, column_key, elements)


async def decrypt_assignments(backend: Any, assignments: list[DecryptAssignment]) -> None:
    """Decrypt every assignment in one batch, keeping the work off the event loop."""

    if not assignments:
        return

    ciphertexts = [assignment["ciphertext"] for assignment in assignments]

    apply_plaintexts(assignments, await decrypt_off_loop(backend, ciphertexts))


def decrypt_assignments_sync(backend: Any, assignments: list[DecryptAssignment]) -> None:
    """Decrypt every assignment in one batch on the calling thread."""

    if not assignments:
        return

    ciphertexts = [assignment["ciphertext"] for assignment in assignments]

    apply_plaintexts(assignments, decrypt_batch(backend, ciphertexts))


async def decrypt_rows(rows: Iterable[Any], *columns: InstrumentedAttribute | str) -> None:
    """Decrypt the given columns across every row in one batch."""

    if not columns:
        return

    backend = resolve_backend()
    assignments = collect_row_assignments(rows, (column_key(c) for c in columns))

    await decrypt_assignments(backend, assignments)


async def decrypt_values(values: Iterable[Any]) -> list[Any]:
    """Decrypt a flat iterable of ciphertexts, preserving non-encrypted positions as-is."""

    values_list = list(values)
    if not values_list:
        return []

    backend = resolve_backend()
    indexes: list[int] = []
    encrypted_blobs: list[bytes] = []
    for index, value in enumerate(values_list):
        if isinstance(value, EncryptedValue):
            encrypted_blobs.append(bytes(value))
            indexes.append(index)

    if not encrypted_blobs:
        return values_list

    plaintexts = await decrypt_off_loop(backend, encrypted_blobs)

    for index, plaintext in zip(indexes, plaintexts):
        values_list[index] = decode_value(plaintext)

    return values_list


def collect_encrypted_cells(
    entities: Any | Iterable[Any] | None,
    assignments: list[DecryptAssignment],
    visited: set[int],
) -> None:
    """Append an assignment per deferred-encrypted cell, walking loaded relationships."""

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
            if not isinstance(column.type, DeferrableEncryptedType) or not column.type.deferred:
                continue

            assignments.extend(cell_assignments(entity, column.key, state.dict.get(column.key)))

        unloaded = state.unloaded
        for relationship in state.mapper.relationships:
            if relationship.key in unloaded:
                continue
            related = state.dict.get(relationship.key)
            if related is None:
                continue
            if relationship.uselist:
                collect_encrypted_cells(list(related), assignments, visited)
            else:
                collect_encrypted_cells(related, assignments, visited)


def collect_entity_assignments(entities: Any | Iterable[Any] | None) -> list[DecryptAssignment]:
    """Build the assignments for every deferred cell on these entities and loaded relationships."""

    assignments: list[DecryptAssignment] = []
    collect_encrypted_cells(entities, assignments, set())

    return assignments


async def bulk_decrypt_entities(entities: Any | Iterable[Any] | None) -> None:
    """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

    assignments = collect_entity_assignments(entities)

    if assignments:
        await decrypt_assignments(resolve_backend(), assignments)


def bulk_decrypt_entities_sync(entities: Any | Iterable[Any] | None) -> None:
    """Decrypt every deferred encrypted column for a consumer on a synchronous session."""

    assignments = collect_entity_assignments(entities)

    if assignments:
        decrypt_assignments_sync(resolve_backend(), assignments)


def pop_pending_rows(session: AsyncSession) -> list[Any]:
    """Remove this session's pending-decrypt bucket and flatten it into a row list."""

    pending = session.info.pop(PENDING_DECRYPT_KEY, None) or {}

    return [row for rows in pending.values() for row in rows]


async def decrypt_pending_fields(session: AsyncSession) -> None:
    """Force-decrypt every encrypted column on every instance bucketed in this session."""

    await bulk_decrypt_entities(pop_pending_rows(session))


def decrypt_pending_fields_sync(session: Any) -> None:
    """Force-decrypt this session's bucketed instances for a consumer on a synchronous session."""

    bulk_decrypt_entities_sync(pop_pending_rows(session))


async def finalize_sqlalchemy_session(session: AsyncSession) -> None:
    """Commit to release the pooled connection, then run the captured pending decrypt batch."""

    rows = pop_pending_rows(session)

    if session.in_transaction():
        await session.commit()

    await bulk_decrypt_entities(rows)


__all__ = [
    "bulk_decrypt_entities",
    "bulk_decrypt_entities_sync",
    "collect_encrypted_cells",
    "decrypt_pending_fields",
    "decrypt_pending_fields_sync",
    "decrypt_rows",
    "decrypt_values",
    "finalize_sqlalchemy_session",
]
