import asyncio
from collections import defaultdict
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

from pydantic_encryption.integrations.sqlalchemy import (
    AutoDecryptAsyncSession,
    DeferredDecryptMixin,
)
from pydantic_encryption.integrations.sqlalchemy.bulk import (
    AUTO_DECRYPT_ENABLED_KEY,
    PENDING_DECRYPT_KEY,
    _collect_encrypted_cells,
    _on_orm_load,
)
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


class _AutoDecryptBase(DeclarativeBase):
    """Isolated declarative base for AutoDecryptAsyncSession unit tests."""


class _AutoDecryptUser(_AutoDecryptBase, DeferredDecryptMixin):
    """Mapped class with a string-typed deferred encrypted column."""

    __tablename__ = "_auto_decrypt_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


class _AutoDecryptBlob(_AutoDecryptBase, DeferredDecryptMixin):
    """Mapped class with a bytes-typed deferred encrypted column to test idempotency."""

    __tablename__ = "_auto_decrypt_blob"

    id: Mapped[int] = mapped_column(primary_key=True)
    payload: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


def _encrypt(value: Any) -> bytes:
    """Encrypt a value via the SQLAlchemyEncryptedValue write path."""

    return SQLAlchemyEncryptedValue().process_bind_param(value, None)


def _wrap(value: Any) -> EncryptedValue:
    """Wrap ciphertext in EncryptedValue the way process_result_value does on read."""

    return EncryptedValue(_encrypt(value))


class TestOnOrmLoadListener:
    """Test that _on_orm_load collects instances only when the auto-decrypt flag is set."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_collects_when_flag_enabled(self):
        session = SimpleNamespace(info={AUTO_DECRYPT_ENABLED_KEY: True})
        context = SimpleNamespace(session=session)
        instance = _AutoDecryptUser(id=1)

        _on_orm_load(instance, context)

        bucket = session.info[PENDING_DECRYPT_KEY]
        assert bucket[_AutoDecryptUser] == [instance]

    def test_noop_when_flag_missing(self):
        session = SimpleNamespace(info={})
        context = SimpleNamespace(session=session)

        _on_orm_load(_AutoDecryptUser(id=1), context)

        assert PENDING_DECRYPT_KEY not in session.info

    def test_noop_when_session_is_none(self):
        context = SimpleNamespace(session=None)

        _on_orm_load(_AutoDecryptUser(id=1), context)  # no exception

    def test_noop_when_context_is_none(self):
        _on_orm_load(_AutoDecryptUser(id=1), None)  # no exception

    def test_groups_by_class(self):
        session = SimpleNamespace(info={AUTO_DECRYPT_ENABLED_KEY: True})
        context = SimpleNamespace(session=session)
        user_a = _AutoDecryptUser(id=1)
        user_b = _AutoDecryptUser(id=2)
        blob = _AutoDecryptBlob(id=1)

        _on_orm_load(user_a, context)
        _on_orm_load(user_b, context)
        _on_orm_load(blob, context)

        bucket = session.info[PENDING_DECRYPT_KEY]
        assert bucket[_AutoDecryptUser] == [user_a, user_b]
        assert bucket[_AutoDecryptBlob] == [blob]


class TestAutoDecryptAsyncSession:
    """Test AutoDecryptAsyncSession init and drain behavior."""

    def test_init_sets_enabled_flag(self):
        session = AutoDecryptAsyncSession(bind=None)

        assert session.info[AUTO_DECRYPT_ENABLED_KEY] is True

    def test_drain_decrypts_every_pending_class(self):
        session = AutoDecryptAsyncSession(bind=None)
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        blob = _AutoDecryptBlob(id=1, payload=_wrap(b"shh"))

        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_AutoDecryptUser].append(user)
        bucket[_AutoDecryptBlob].append(blob)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(session._drain_pending_decrypt())

        assert user.email == "a@x.com"
        assert blob.payload == b"shh"
        assert PENDING_DECRYPT_KEY not in session.info

    def test_drain_noop_when_bucket_empty(self):
        session = AutoDecryptAsyncSession(bind=None)

        asyncio.run(session._drain_pending_decrypt())  # no exception

        assert PENDING_DECRYPT_KEY not in session.info

    def test_execute_drains_after_super_execute(self):
        session = AutoDecryptAsyncSession(bind=None)
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_AutoDecryptUser].append(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        sentinel_result = object()

        async def fake_super_execute(*args, **kwargs):
            return sentinel_result

        session.__class__.__bases__[0].execute = AsyncMock(side_effect=fake_super_execute)
        try:
            result = asyncio.run(session.execute("SELECT 1"))
        finally:
            del session.__class__.__bases__[0].execute

        assert result is sentinel_result
        assert user.email == "a@x.com"

    def test_get_drains_after_super_get(self):
        session = AutoDecryptAsyncSession(bind=None)
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_AutoDecryptUser].append(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        async def fake_super_get(*args, **kwargs):
            return user

        session.__class__.__bases__[0].get = AsyncMock(side_effect=fake_super_get)
        try:
            result = asyncio.run(session.get(_AutoDecryptUser, 1))
        finally:
            del session.__class__.__bases__[0].get

        assert result is user
        assert user.email == "a@x.com"

    def test_refresh_drains_after_super_refresh(self):
        session = AutoDecryptAsyncSession(bind=None)
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_AutoDecryptUser].append(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        async def fake_super_refresh(*args, **kwargs):
            return None

        session.__class__.__bases__[0].refresh = AsyncMock(side_effect=fake_super_refresh)
        try:
            asyncio.run(session.refresh(user))
        finally:
            del session.__class__.__bases__[0].refresh

        assert user.email == "a@x.com"

    def test_merge_drains_after_super_merge(self):
        session = AutoDecryptAsyncSession(bind=None)
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_AutoDecryptUser].append(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        async def fake_super_merge(*args, **kwargs):
            return user

        session.__class__.__bases__[0].merge = AsyncMock(side_effect=fake_super_merge)
        try:
            result = asyncio.run(session.merge(user))
        finally:
            del session.__class__.__bases__[0].merge

        assert result is user
        assert user.email == "a@x.com"


class TestBytesColumnIdempotency:
    """Regression test: BYTES-typed columns must not double-decrypt under repeated load events."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_collect_skips_already_decrypted_bytes_plaintext(self):
        blob = _AutoDecryptBlob(id=1, payload=_wrap(b"shh"))

        asyncio.run(_AutoDecryptBlob.decrypt_many([blob]))

        assert blob.payload == b"shh"
        assert not isinstance(blob.payload, EncryptedValue)

        collected: dict[tuple[type, str], list[Any]] = {}
        visited: set[int] = set()
        _collect_encrypted_cells(blob, collected, visited)

        assert collected == {}


class TestDrainParallelism:
    """Regression test: the drain must fan out every class's cells in a single gather."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_drain_gathers_cells_across_classes_in_parallel(self):
        session = AutoDecryptAsyncSession(bind=None)
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        blob = _AutoDecryptBlob(id=1, payload=_wrap(b"shh"))

        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_AutoDecryptUser].append(user)
        bucket[_AutoDecryptBlob].append(blob)
        session.info[PENDING_DECRYPT_KEY] = bucket

        gather_calls: list[int] = []
        original_gather = asyncio.gather

        async def counting_gather(*coros, **kwargs):
            gather_calls.append(len(coros))
            return await original_gather(*coros, **kwargs)

        asyncio.gather = counting_gather  # type: ignore[assignment]
        try:
            asyncio.run(session._drain_pending_decrypt())
        finally:
            asyncio.gather = original_gather  # type: ignore[assignment]

        assert user.email == "a@x.com"
        assert blob.payload == b"shh"
        assert gather_calls, "expected asyncio.gather to be invoked by the drain"
        assert max(gather_calls) >= 2, (
            "expected at least one gather to span both classes' cells; "
            f"got gather widths {gather_calls}"
        )


class TestNoDirtyAfterDecrypt:
    """Regression test: decrypted columns must not be marked dirty for the next flush."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_decrypt_many_does_not_mark_column_dirty(self):
        user = _AutoDecryptUser(id=1, email=_wrap("a@x.com"))
        state = sa_inspect(user)
        state._commit_all(state.dict)

        assert "email" not in state.committed_state

        asyncio.run(_AutoDecryptUser.decrypt_many([user]))

        assert user.email == "a@x.com"
        assert "email" not in state.committed_state
