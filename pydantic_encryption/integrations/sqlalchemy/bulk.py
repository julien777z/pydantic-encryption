import asyncio
from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Self

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import event, inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import object_session
from sqlalchemy.orm.attributes import InstrumentedAttribute, set_committed_value

from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy._async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.serialization import decode_value
from pydantic_encryption.types import EncryptedValue

PENDING_DECRYPT_KEY = "__pydantic_encryption_pending_decrypt__"


def _column_name(column: InstrumentedAttribute | str) -> str:
    if isinstance(column, str):
        return column
    return column.key


def _read_raw_cell(row: Any, name: str) -> Any:
    """Read a column's stored value via ORM state, bypassing attribute descriptors."""

    state = sa_inspect(row, raiseerr=False)
    if state is not None and hasattr(state, "dict"):
        return state.dict.get(name)
    return getattr(row, name, None)


def _resolve_concurrency(concurrency: int | None) -> int | None:
    """Resolve to settings.DECRYPT_CONCURRENCY when the caller didn't supply one."""

    if concurrency is not None:
        return concurrency
    default = settings.DECRYPT_CONCURRENCY
    return default if default and default > 0 else None


def _build_decrypt_cell(
    concurrency: int | None,
    caller_name: str,
):
    """Build a single-cell decrypt coroutine factory with optional semaphore."""

    if settings.ENCRYPTION_METHOD is None:
        raise ValueError(f"ENCRYPTION_METHOD must be set to use {caller_name}.")

    backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
    effective = _resolve_concurrency(concurrency)
    semaphore = asyncio.Semaphore(effective) if effective is not None else None

    async def decrypt_cell(ciphertext: bytes) -> Any:
        if semaphore is not None:
            async with semaphore:
                plaintext = await backend.async_decrypt(ciphertext)
        else:
            plaintext = await backend.async_decrypt(ciphertext)

        return decode_value(plaintext)

    return decrypt_cell


async def async_decrypt_rows(
    rows: Iterable[Any],
    *columns: InstrumentedAttribute | str,
    concurrency: int | None = None,
) -> None:
    """Decrypt the given columns across every row in one asyncio.gather."""

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
            value = _read_raw_cell(row, name)
            if not isinstance(value, EncryptedValue):
                continue
            ciphertext = bytes(value)
            coros.append(decrypt_cell(ciphertext))
            assignments.append((row, name))

    if not coros:
        return

    results = await asyncio.gather(*coros)
    for (row, name), plaintext in zip(assignments, results):
        _set_decrypted(row, name, plaintext)


def _set_decrypted(row: Any, name: str, plaintext: Any) -> None:
    """Commit a decrypted value on a row without marking it dirty for the next flush."""

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
    """Decrypt a flat iterable of ciphertexts, preserving None and plaintext passthrough."""

    values_list = list(values)
    if not values_list:
        return []

    decrypt_cell = _build_decrypt_cell(concurrency, "async_decrypt_values")

    indexed: list[tuple[int, Any]] = []
    coros = []
    for index, value in enumerate(values_list):
        if not isinstance(value, EncryptedValue):
            continue
        ciphertext = bytes(value)
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
    """Walk entities + loaded relationships and decrypt every deferred cell."""

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
                _collect_encrypted_cells(list(related), collected, visited)
            else:
                _collect_encrypted_cells(related, collected, visited)


def _pending_siblings(session: Any, cls: type) -> list[Any]:
    """Pending-decrypt instances of cls in session (empty list if absent)."""

    if session is None:
        return []
    info = getattr(session, "info", None)
    if not info:
        return []
    bucket = info.get(PENDING_DECRYPT_KEY)
    if not bucket:
        return []
    return list(bucket.get(cls, []))


def _decrypt_column_batch_sync(rows: list[Any], column_key: str) -> None:
    """Sync fallback used outside any greenlet context."""

    if settings.ENCRYPTION_METHOD is None:
        raise ValueError("ENCRYPTION_METHOD must be set to decrypt on attribute access.")

    backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
    for row in rows:
        value = _read_raw_cell(row, column_key)
        if not isinstance(value, EncryptedValue):
            continue
        ciphertext = bytes(value)
        plaintext = decode_value(backend.decrypt(ciphertext))
        _set_decrypted(row, column_key, plaintext)


class _DecryptOnAccessDescriptor:
    """InstrumentedAttribute wrapper that batch-decrypts one column across session siblings on first read."""

    __slots__ = ("_wrapped", "_cls", "_column_key")

    def __init__(self, wrapped: Any, cls: type, column_key: str) -> None:
        self._wrapped = wrapped
        self._cls = cls
        self._column_key = column_key

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self._wrapped
        value = self._wrapped.__get__(instance, owner)
        if isinstance(value, EncryptedValue):
            session = object_session(instance)
            siblings = _pending_siblings(session, self._cls) or [instance]
            run_async_or_sync(
                async_decrypt_rows,
                _decrypt_column_batch_sync,
                siblings,
                self._column_key,
            )
            value = self._wrapped.__get__(instance, owner)
        return value

    def __set__(self, instance: Any, value: Any) -> None:
        self._wrapped.__set__(instance, value)

    def __delete__(self, instance: Any) -> None:
        self._wrapped.__delete__(instance)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)


def _install_decrypt_hooks(mapper, class_) -> None:
    """Mark encrypted columns deferred and wrap them with the on-access descriptor."""

    for column in mapper.columns:
        if not isinstance(column.type, SQLAlchemyEncryptedValue):
            continue

        if not column.type._deferred:
            column.type = column.type.copy()
            column.type._deferred = True

        column_key = column.key
        existing = class_.__dict__.get(column_key)
        if isinstance(existing, _DecryptOnAccessDescriptor):
            continue

        wrapped = getattr(class_, column_key, None)
        if wrapped is None:
            continue

        try:
            setattr(class_, column_key, _DecryptOnAccessDescriptor(wrapped, class_, column_key))
        except (AttributeError, TypeError):
            continue


def _on_orm_load(instance: Any, context: Any) -> None:
    """Add a freshly loaded instance to the session's pending-decrypt bucket."""

    if context is None:
        return
    session = context.session
    if session is None:
        return
    bucket: dict[type, list[Any]] = session.info.setdefault(PENDING_DECRYPT_KEY, defaultdict(list))
    bucket[type(instance)].append(instance)


def _on_orm_refresh(instance: Any, context: Any, attrs: Any) -> None:
    """Re-add a refreshed instance to the session's pending-decrypt bucket."""

    _on_orm_load(instance, context)


class DeferredDecryptMixin:
    """Defer encrypted-column decryption until first attribute access, batched per column."""

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", _install_decrypt_hooks)
        event.listen(cls, "load", _on_orm_load)
        event.listen(cls, "refresh", _on_orm_refresh)

    async def decrypt(self) -> Self:
        """Decrypt every deferred encrypted column on this instance and loaded relationships."""

        await _bulk_decrypt(self)

        return self

    @classmethod
    async def decrypt_many(cls, entities: Any | Iterable[Any] | None) -> None:
        """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

        await _bulk_decrypt(entities)


__all__ = ["async_decrypt_rows", "async_decrypt_values", "DeferredDecryptMixin"]
