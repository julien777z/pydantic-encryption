import asyncio
from typing import Any, Iterable, Self

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import Select, event, inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue


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

    if isinstance(entities, (list, tuple, set, frozenset)):
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
            if not isinstance(value, (bytes, bytearray)):
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


class DeferredDecryptMixin:
    """Mixin that auto-defers SQLAlchemyEncryptedValue columns and adds async decrypt helpers.

    Every ``SQLAlchemyEncryptedValue`` column on a class that inherits this mixin returns
    ``EncryptedValue(bytes)`` on read instead of plaintext; call ``decrypt()`` /
    ``decrypt_many()`` / ``scalar_one_or_none()`` / ``scalars_all()`` to decrypt in bulk.
    ``SQLAlchemyPGEncryptedArray`` columns are not affected and still decrypt inline.
    """

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", _mark_encrypted_columns_deferred)

    async def decrypt(self) -> Self:
        """Decrypt deferred encrypted columns on this instance and any loaded relationships."""

        await _bulk_decrypt(self)

        return self

    @classmethod
    async def decrypt_many(cls, entities: Any | Iterable[Any] | None) -> None:
        """Decrypt deferred encrypted columns on the given entities (single, iterable, or None) and any loaded relationships."""

        await _bulk_decrypt(entities)

    @classmethod
    async def scalar_one_or_none(cls, session: AsyncSession, statement: Select) -> Self | None:
        """Execute a SELECT and return a single decrypted scalar, or None."""

        entity = (await session.execute(statement)).scalar_one_or_none()

        await _bulk_decrypt(entity)

        return entity

    @classmethod
    async def scalars_all(cls, session: AsyncSession, statement: Select) -> list[Self]:
        """Execute a SELECT and return all decrypted scalars as a list."""

        rows = list((await session.execute(statement)).scalars().all())

        await _bulk_decrypt(rows)

        return rows


__all__ = ["async_decrypt_rows", "DeferredDecryptMixin"]
