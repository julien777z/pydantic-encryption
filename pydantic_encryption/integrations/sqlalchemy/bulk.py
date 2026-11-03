import asyncio
from collections.abc import Iterable
from typing import TypeVar

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.adapters.registry import configured_encryption_backend
from pydantic_encryption.context import derive_declared_context
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    encrypted_column_type,
)
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    read_raw_cell,
    set_decrypted,
)
from pydantic_encryption.serialization import EncryptableValue, decode_value
from pydantic_encryption.types import EncryptedValue

ValueT = TypeVar("ValueT")


def column_key(column: InstrumentedAttribute[object] | str) -> str:
    """Return the column key for an InstrumentedAttribute or string column name."""

    return column if isinstance(column, str) else column.key


def collect_row_assignments(
    rows: Iterable[object], column_keys: Iterable[str]
) -> list[tuple[object, str, bytes, bytes]]:
    """Build ``(row, key, ciphertext, context)`` tuples for every encrypted cell across rows."""

    column_keys = list(column_keys)
    assignments: list[tuple[object, str, bytes, bytes]] = []

    for row in rows:
        for key in column_keys:
            value = read_raw_cell(row, key)

            if isinstance(value, EncryptedValue):
                column = sa_inspect(type(row), raiseerr=True).columns[key]
                assignments.append((row, key, bytes(value), encrypted_column_type(column).context_for(row)))

    return assignments


async def open_assignments(
    backend: type[EncryptionAdapter], assignments: list[tuple[object, str, bytes, bytes]]
) -> list[tuple[object, Exception]]:
    """Decrypt every ``(row, key, ciphertext, context)`` tuple concurrently, returning the cells that failed.

    Every cell that opens is written back, whatever happens to the others.
    """

    results = await asyncio.gather(
        *(
            backend.async_decrypt(ciphertext, associated_data=context)
            for _, _, ciphertext, context in assignments
        ),
        return_exceptions=True,
    )
    failures: list[tuple[object, Exception]] = []

    for (row, key, _, _), result in zip(assignments, results):
        if isinstance(result, Exception):
            failures.append((row, result))

            continue

        if isinstance(result, BaseException):
            raise result

        set_decrypted(row, key, decode_value(result))

    return failures


def open_assignments_sync(
    backend: type[EncryptionAdapter], assignments: list[tuple[object, str, bytes, bytes]]
) -> list[tuple[object, Exception]]:
    """Decrypt every ``(row, key, ciphertext, context)`` tuple in turn, returning the cells that failed."""

    failures: list[tuple[object, Exception]] = []

    for row, key, ciphertext, context in assignments:
        try:
            plaintext = backend.decrypt(ciphertext, associated_data=context)
        except Exception as exc:
            failures.append((row, exc))

            continue

        set_decrypted(row, key, decode_value(plaintext))

    return failures


def raise_failures(failures: list[tuple[object, Exception]]) -> None:
    """Raise every cell that failed to decrypt as one group, once the cells that opened are written back."""

    if failures:
        raise ExceptionGroup("Some encrypted cells could not be decrypted.", [exc for _, exc in failures])


async def open_rows(
    rows: Iterable[object], *columns: InstrumentedAttribute[object] | str
) -> list[tuple[object, Exception]]:
    """Decrypt the given columns across every row concurrently, returning the cells that failed."""

    if not columns:
        return []

    assignments = collect_row_assignments(rows, (column_key(c) for c in columns))

    return await open_assignments(configured_encryption_backend(), assignments)


def open_rows_sync(
    rows: Iterable[object], *columns: InstrumentedAttribute[object] | str
) -> list[tuple[object, Exception]]:
    """Decrypt the given columns across every row in turn, returning the cells that failed."""

    if not columns:
        return []

    assignments = collect_row_assignments(rows, (column_key(c) for c in columns))

    return open_assignments_sync(configured_encryption_backend(), assignments)


async def decrypt_rows(rows: Iterable[object], *columns: InstrumentedAttribute[object] | str) -> None:
    """Decrypt the given columns across every row concurrently, raising every cell that failed."""

    raise_failures(await open_rows(rows, *columns))


def decrypt_rows_sync(rows: Iterable[object], *columns: InstrumentedAttribute[object] | str) -> None:
    """Decrypt the given columns across every row synchronously, raising every cell that failed."""

    raise_failures(open_rows_sync(rows, *columns))


def resolve_context(context: InstrumentedAttribute[object] | str) -> bytes:
    """Return the context a column binds to, or the one a name binds to as the column type's declared name."""

    if isinstance(context, InstrumentedAttribute):
        return encrypted_column_type(context.property.columns[0]).bound_context()

    return derive_declared_context(context)


async def decrypt_values(
    values: Iterable[ValueT], *, context: InstrumentedAttribute[object] | str
) -> list[ValueT | EncryptableValue]:
    """Decrypt a flat iterable of ciphertexts from one column, preserving other positions as-is.

    ``context`` is the column's attribute, or the name the column type was declared with, which binds
    here as ``SQLAlchemyEncryptedValue(name)`` binds it.
    """

    values_list: list[ValueT | EncryptableValue] = list(values)

    if not values_list:
        return []

    backend = configured_encryption_backend()
    associated_data = resolve_context(context)
    indexes: list[int] = []
    encrypted_blobs: list[bytes] = []

    for index, value in enumerate(values_list):
        if isinstance(value, EncryptedValue):
            encrypted_blobs.append(bytes(value))
            indexes.append(index)

    if not encrypted_blobs:
        return values_list

    async with asyncio.TaskGroup() as tg:
        tasks = [
            tg.create_task(backend.async_decrypt(blob, associated_data=associated_data))
            for blob in encrypted_blobs
        ]

    for index, task in zip(indexes, tasks):
        values_list[index] = decode_value(task.result())

    return values_list


def collect_encrypted_cells(
    entities: object | Iterable[object] | None,
    collected: dict[tuple[type[object], str], list[object]],
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

        for attribute, column in state.mapper.columns.items():
            if not isinstance(column.type, SQLAlchemyEncryptedValue):
                continue
            if not column.type.deferred:
                continue
            if isinstance(state.dict.get(attribute), EncryptedValue):
                collected.setdefault((type(entity), attribute), []).append(entity)

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


async def bulk_decrypt_entities(entities: object | Iterable[object] | None) -> None:
    """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

    collected: dict[tuple[type[object], str], list[object]] = {}

    collect_encrypted_cells(entities, collected, set())

    if not collected:
        return

    assignments: list[tuple[object, str, bytes, bytes]] = []

    for (_, column_key), rows in collected.items():
        assignments.extend(collect_row_assignments(rows, (column_key,)))

    raise_failures(await open_assignments(configured_encryption_backend(), assignments))


def pop_pending_rows(session: AsyncSession) -> list[object]:
    """Remove this session's pending-decrypt bucket and flatten it into the rows the session still holds."""

    pending = session.info.pop(PENDING_DECRYPT_KEY, None) or {}

    return [row for rows in pending.values() for row in rows if row in session]


async def decrypt_pending_fields(session: AsyncSession) -> None:
    """Force-decrypt every encrypted column on every instance bucketed in this session."""

    await bulk_decrypt_entities(pop_pending_rows(session))


async def finalize_sqlalchemy_session(session: AsyncSession) -> None:
    """Commit to release the pooled connection, then run the captured pending decrypt batch."""

    rows = pop_pending_rows(session)

    if session.in_transaction():
        await session.commit()

    await bulk_decrypt_entities(rows)


__all__ = [
    "bulk_decrypt_entities",
    "collect_encrypted_cells",
    "decrypt_pending_fields",
    "decrypt_rows",
    "decrypt_rows_sync",
    "decrypt_values",
    "finalize_sqlalchemy_session",
]
