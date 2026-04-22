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

AUTO_DECRYPT_ENABLED_KEY = "__pydantic_encryption_auto_decrypt__"
PENDING_DECRYPT_KEY = "__pydantic_encryption_pending_decrypt__"


def _column_name(column: InstrumentedAttribute | str) -> str:
    if isinstance(column, str):
        return column
    return column.key


def _read_raw_cell(row: Any, name: str) -> Any:
    """Read a column's stored value from ORM state, bypassing any on-access descriptor."""

    state = sa_inspect(row, raiseerr=False)
    if state is not None and hasattr(state, "dict"):
        return state.dict.get(name)
    return getattr(row, name, None)


def _resolve_concurrency(concurrency: int | None) -> int | None:
    """Fall back to the global DECRYPT_CONCURRENCY setting when a caller doesn't pass one."""

    if concurrency is not None:
        return concurrency
    default = settings.DECRYPT_CONCURRENCY
    return default if default and default > 0 else None


def _build_decrypt_cell(
    concurrency: int | None,
    caller_name: str,
):
    """Build a single decrypt-one-cell coroutine factory shared by the bulk helpers."""

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
    """Bulk-decrypt deferred encrypted columns across many rows in parallel.

    Each non-``None`` ``(row, column)`` cell becomes one ``async_decrypt`` task.
    All tasks run via a single ``asyncio.gather``. Concurrency defaults to
    ``settings.DECRYPT_CONCURRENCY`` (``32``) unless overridden; pass
    ``concurrency=None`` explicitly and set ``DECRYPT_CONCURRENCY=0`` to disable
    the cap entirely.

    Columns may be passed as SQLAlchemy ``InstrumentedAttribute`` (e.g.
    ``User.email``) or plain strings (``"email"``). Decrypted values are
    written back via ``set_committed_value`` so they do not mark the row as
    dirty for the next flush.
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
            value = _read_raw_cell(row, name)
            if not isinstance(value, (bytes, bytearray)):
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


def _pending_siblings(session: Any, cls: type) -> list[Any]:
    """Pull pending-decrypt instances for `cls` from the session bucket (empty list if absent)."""

    if session is None:
        return []
    info = getattr(session, "info", None)
    if not info:
        return []
    bucket = info.get(PENDING_DECRYPT_KEY)
    if not bucket:
        return []
    return list(bucket.get(cls, []))


async def _decrypt_column_batch_async(rows: list[Any], column_key: str) -> None:
    """Batch-decrypt one encrypted column across every row via a single asyncio.gather."""

    await async_decrypt_rows(rows, column_key)


def _decrypt_column_batch_sync(rows: list[Any], column_key: str) -> None:
    """Sync fallback used when no greenlet context is available (tests, CLI scripts)."""

    if settings.ENCRYPTION_METHOD is None:
        raise ValueError("ENCRYPTION_METHOD must be set to decrypt on attribute access.")

    backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
    for row in rows:
        value = _read_raw_cell(row, column_key)
        if not isinstance(value, (bytes, bytearray)):
            continue
        ciphertext = bytes(value) if not isinstance(value, bytes) else value
        plaintext = decode_value(backend.decrypt(ciphertext))
        _set_decrypted(row, column_key, plaintext)


class _DecryptOnAccessDescriptor:
    """Class-level wrapper around an encrypted column's ``InstrumentedAttribute`` that
    batch-decrypts the column across all pending-session siblings on first read.

    - Class-level access (e.g. ``Contractor.first_name == "x"``) returns the wrapped
      ``InstrumentedAttribute`` unchanged, so ORM query construction is unaffected.
    - Instance-level access triggers a per-column batch decrypt when the stored cell
      is still an ``EncryptedValue``; subsequent reads get the plaintext for free.
    """

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
                _decrypt_column_batch_async,
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
    """Mark encrypted columns as deferred and install on-access decrypt descriptors.

    Replaces each encrypted column's class attribute with a descriptor that
    delegates to the original ``InstrumentedAttribute`` but decrypts on first
    read. Safe to call multiple times — already-installed descriptors are
    left in place.
    """

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
    """Collect freshly loaded DeferredDecryptMixin instances into the session's pending bucket."""

    if context is None:
        return
    session = context.session
    if session is None:
        return
    bucket: dict[type, list[Any]] = session.info.setdefault(PENDING_DECRYPT_KEY, defaultdict(list))
    bucket[type(instance)].append(instance)


def _on_orm_refresh(instance: Any, context: Any, attrs: Any) -> None:
    """Collect refreshed DeferredDecryptMixin instances into the session's pending bucket."""

    _on_orm_load(instance, context)


class DeferredDecryptMixin:
    """Mixin that defers decryption of ``SQLAlchemyEncryptedValue`` columns until the
    first attribute access, then batch-decrypts each column across all sibling
    instances loaded into the same session.

    No call-site changes are needed: reading ``contractor.first_name`` on any
    loaded contractor decrypts ``first_name`` across every contractor in the
    session in one ``asyncio.gather``; columns the response never reads stay
    encrypted and cost nothing.

    ``decrypt()`` / ``decrypt_many()`` remain available for the rare call sites
    that want to pre-warm many columns at once (e.g. serializing a large
    pre-built payload outside of any session context).
    """

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", _install_decrypt_hooks)
        event.listen(cls, "load", _on_orm_load)
        event.listen(cls, "refresh", _on_orm_refresh)

    async def decrypt(self) -> Self:
        """Decrypt deferred encrypted columns on this instance and any loaded relationships."""

        await _bulk_decrypt(self)

        return self

    @classmethod
    async def decrypt_many(cls, entities: Any | Iterable[Any] | None) -> None:
        """Decrypt deferred encrypted columns on the given entities (single, iterable, or None) and any loaded relationships."""

        await _bulk_decrypt(entities)


__all__ = ["async_decrypt_rows", "async_decrypt_values", "DeferredDecryptMixin"]
