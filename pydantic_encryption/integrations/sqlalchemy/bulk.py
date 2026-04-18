import asyncio
from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Self

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import event, inspect as sa_inspect
from sqlalchemy.orm.attributes import InstrumentedAttribute, set_committed_value

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue

AUTO_DECRYPT_ENABLED_KEY = "__pydantic_encryption_auto_decrypt__"
PENDING_DECRYPT_KEY = "__pydantic_encryption_pending_decrypt__"


def _column_name(column: InstrumentedAttribute | str) -> str:
    if isinstance(column, str):
        return column
    return column.key


def _build_decrypt_cell(
    concurrency: int | None,
    caller_name: str,
):
    """Build a single decrypt-one-cell coroutine factory shared by the bulk helpers."""

    if settings.ENCRYPTION_METHOD is None:
        raise ValueError(f"ENCRYPTION_METHOD must be set to use {caller_name}.")

    backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
    type_helper = SQLAlchemyEncryptedValue()
    semaphore = asyncio.Semaphore(concurrency) if concurrency is not None else None

    async def decrypt_cell(ciphertext: bytes) -> Any:
        if semaphore is not None:
            async with semaphore:
                plaintext = await backend.async_decrypt(ciphertext)
        else:
            plaintext = await backend.async_decrypt(ciphertext)

        return type_helper._deserialize_value(plaintext)

    return decrypt_cell


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

    decrypt_cell = _build_decrypt_cell(concurrency, "async_decrypt_rows")
    column_names = [_column_name(c) for c in columns]

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
        _set_decrypted(row, name, plaintext)


def _set_decrypted(row: Any, name: str, plaintext: Any) -> None:
    """Set a decrypted value on a row without marking the column as dirty for the next flush."""

    state = sa_inspect(row, raiseerr=False)
    if state is None or not hasattr(state, "mapper"):
        setattr(row, name, plaintext)
        return
    set_committed_value(row, name, plaintext)


async def async_decrypt_values(
    values: Iterable[Any],
    *,
    concurrency: int | None = None,
) -> list[Any]:
    """Bulk-decrypt a flat iterable of ciphertexts, preserving ``None`` positions.

    Returned list has the same length as ``values`` with plaintexts substituted
    for each non-``None`` input. Any cell already holding plaintext (not
    ``bytes``/``bytearray``) is passed through untouched, matching the read-
    path convention used by ``async_decrypt_rows``.
    """

    values_list = list(values)
    if not values_list:
        return []

    decrypt_cell = _build_decrypt_cell(concurrency, "async_decrypt_values")

    indexed: list[tuple[int, Any]] = []
    coros = []
    for index, value in enumerate(values_list):
        if value is None:
            continue
        if not isinstance(value, (bytes, bytearray)):
            continue
        ciphertext = bytes(value) if not isinstance(value, bytes) else value
        coros.append(decrypt_cell(ciphertext))
        indexed.append((index, value))

    if not coros:
        return values_list

    results = await asyncio.gather(*coros)
    out = list(values_list)
    for (index, _), plaintext in zip(indexed, results):
        out[index] = plaintext

    return out


async def _bulk_decrypt(entities: Any | Iterable[Any] | None) -> None:
    """Walk entities + loaded relationships and batch-decrypt deferred encrypted cells."""

    collected: dict[tuple[type, str], list[Any]] = {}
    visited: set[int] = set()
    _collect_encrypted_cells(entities, collected, visited)

    if not collected:
        return

    awaitables = [
        async_decrypt_rows(rows, getattr(cls, column_key))
        for (cls, column_key), rows in collected.items()
    ]

    await asyncio.gather(*awaitables)


def _collect_encrypted_cells(
    entities: Any | Iterable[Any] | None,
    collected: dict[tuple[type, str], list[Any]],
    visited: set[int],
) -> None:
    """Walk entities (and loaded relationships) and group rows by (class, column) for deferred-encrypted cells."""

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
                _collect_encrypted_cells(list(related), collected, visited)
            else:
                _collect_encrypted_cells(related, collected, visited)


def _mark_encrypted_columns_deferred(mapper, class_) -> None:
    for column in mapper.columns:
        if not isinstance(column.type, SQLAlchemyEncryptedValue):
            continue
        if column.type._deferred:
            continue
        column.type = column.type.copy()
        column.type._deferred = True


def _on_orm_load(instance: Any, context: Any) -> None:
    """Collect freshly loaded DeferredDecryptMixin instances into the session's pending bucket."""

    session = context.session
    if session is None or not session.info.get(AUTO_DECRYPT_ENABLED_KEY):
        return
    bucket: dict[type, list[Any]] = session.info.setdefault(PENDING_DECRYPT_KEY, defaultdict(list))
    bucket[type(instance)].append(instance)


class DeferredDecryptMixin:
    """Mixin that auto-defers SQLAlchemyEncryptedValue columns and adds async decrypt helpers.

    Every ``SQLAlchemyEncryptedValue`` column on a class that inherits this mixin returns
    ``EncryptedValue(bytes)`` on read instead of plaintext; call ``decrypt()`` /
    ``decrypt_many()`` to decrypt in bulk. ``SQLAlchemyPGEncryptedArray`` columns are not
    affected and still decrypt inline.

    When loaded through :class:`AutoDecryptAsyncSession`, instances are batch-decrypted
    automatically after each ``execute()`` and the explicit decrypt calls are unnecessary.
    """

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", _mark_encrypted_columns_deferred)
        event.listen(cls, "load", _on_orm_load)

    async def decrypt(self) -> Self:
        """Decrypt deferred encrypted columns on this instance and any loaded relationships."""

        await _bulk_decrypt(self)

        return self

    @classmethod
    async def decrypt_many(cls, entities: Any | Iterable[Any] | None) -> None:
        """Decrypt deferred encrypted columns on the given entities (single, iterable, or None) and any loaded relationships."""

        await _bulk_decrypt(entities)


__all__ = ["async_decrypt_rows", "async_decrypt_values", "DeferredDecryptMixin"]
