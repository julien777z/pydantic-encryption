import asyncio
from collections import defaultdict
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from weakref import WeakSet

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin, decrypt_pending_fields
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from pydantic_encryption.integrations.sqlalchemy.bulk import collect_encrypted_cells
from pydantic_encryption.integrations.sqlalchemy.deferred import on_orm_load
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


class AutoDecryptBase(DeclarativeBase):
    """Isolated declarative base for on-access decrypt session-level tests."""


class AutoDecryptUser(AutoDecryptBase, DeferredDecryptMixin):
    """Mapped class with a string-typed deferred encrypted column."""

    __tablename__ = "_auto_decrypt_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


class AutoDecryptBlob(AutoDecryptBase, DeferredDecryptMixin):
    """Mapped class with a bytes-typed deferred encrypted column to test idempotency."""

    __tablename__ = "_auto_decrypt_blob"

    id: Mapped[int] = mapped_column(primary_key=True)
    payload: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


def encrypt_value(value: Any) -> bytes:
    """Encrypt a value via the SQLAlchemyEncryptedValue write path."""

    return SQLAlchemyEncryptedValue().process_bind_param(value, None)


def wrap_encrypted(value: Any) -> EncryptedValue:
    """Wrap ciphertext in EncryptedValue the way process_result_value does on read."""

    return EncryptedValue(encrypt_value(value))


class TestOnOrmLoadListener:
    """Test that on_orm_load collects every loaded instance into the session bucket."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_collects_into_session_bucket(self):
        session = SimpleNamespace(info={})
        context = SimpleNamespace(session=session)
        instance = AutoDecryptUser(id=1)

        on_orm_load(instance, context)

        bucket = session.info[PENDING_DECRYPT_KEY]
        assert instance in bucket[AutoDecryptUser]

    def test_noop_when_session_is_none(self):
        context = SimpleNamespace(session=None)

        on_orm_load(AutoDecryptUser(id=1), context)

    def test_noop_when_context_is_none(self):
        on_orm_load(AutoDecryptUser(id=1), None)

    def test_groups_by_class(self):
        session = SimpleNamespace(info={})
        context = SimpleNamespace(session=session)
        user_a = AutoDecryptUser(id=1)
        user_b = AutoDecryptUser(id=2)
        blob = AutoDecryptBlob(id=1)

        on_orm_load(user_a, context)
        on_orm_load(user_b, context)
        on_orm_load(blob, context)

        bucket = session.info[PENDING_DECRYPT_KEY]
        assert set(bucket[AutoDecryptUser]) == {user_a, user_b}
        assert set(bucket[AutoDecryptBlob]) == {blob}

    def test_refresh_dedups_same_instance(self):
        session = SimpleNamespace(info={})
        context = SimpleNamespace(session=session)
        instance = AutoDecryptUser(id=1)

        on_orm_load(instance, context)
        on_orm_load(instance, context)
        on_orm_load(instance, context)

        bucket = session.info[PENDING_DECRYPT_KEY]
        assert len(bucket[AutoDecryptUser]) == 1


class TestDecryptPendingFields:
    """Test that decrypt_pending_fields drains the session bucket across every pending class."""

    def test_drain_decrypts_every_pending_class(self):
        session = SimpleNamespace(info={})
        user = AutoDecryptUser(id=1, email=wrap_encrypted("a@x.com"))
        blob = AutoDecryptBlob(id=1, payload=wrap_encrypted(b"shh"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[AutoDecryptUser].add(user)
        bucket[AutoDecryptBlob].add(blob)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(decrypt_pending_fields(session))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert sa_inspect(blob).dict["payload"] == b"shh"
        assert PENDING_DECRYPT_KEY not in session.info

    def test_drain_noop_when_bucket_empty(self):
        session = SimpleNamespace(info={})

        asyncio.run(decrypt_pending_fields(session))

        assert PENDING_DECRYPT_KEY not in session.info


class TestBytesColumnIdempotency:
    """Regression test that BYTES-typed columns do not double-decrypt under repeated load events."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_collect_skips_already_decrypted_bytes_plaintext(self):
        blob = AutoDecryptBlob(id=1, payload=wrap_encrypted(b"shh"))

        asyncio.run(AutoDecryptBlob.decrypt_many([blob]))

        assert sa_inspect(blob).dict["payload"] == b"shh"
        assert not isinstance(sa_inspect(blob).dict["payload"], EncryptedValue)

        collected: dict[tuple[type, str], list[Any]] = {}
        visited: set[int] = set()
        collect_encrypted_cells(blob, collected, visited)

        assert collected == {}


class TestDrainParallelism:
    """Test that decrypt_pending_fields fans out every class's cells under one TaskGroup."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_drain_dispatches_cells_across_classes_in_parallel(self):
        session = SimpleNamespace(info={})
        user = AutoDecryptUser(id=1, email=wrap_encrypted("a@x.com"))
        blob = AutoDecryptBlob(id=1, payload=wrap_encrypted(b"shh"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[AutoDecryptUser].add(user)
        bucket[AutoDecryptBlob].add(blob)
        session.info[PENDING_DECRYPT_KEY] = bucket

        live_overlap = 0
        peak_overlap = 0
        original_decrypt = FernetAdapter.decrypt

        async def overlapping_async_decrypt(ciphertext, *, key=None):
            nonlocal live_overlap, peak_overlap
            live_overlap += 1
            peak_overlap = max(peak_overlap, live_overlap)
            try:
                await asyncio.sleep(0)
                return original_decrypt(ciphertext, key=key)
            finally:
                live_overlap -= 1

        with patch.object(FernetAdapter, "async_decrypt", side_effect=overlapping_async_decrypt):
            asyncio.run(decrypt_pending_fields(session))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert sa_inspect(blob).dict["payload"] == b"shh"
        assert peak_overlap >= 2, (
            "expected at least two decrypts to be in flight together across classes; "
            f"observed peak overlap {peak_overlap}"
        )


class TestNoDirtyAfterDecrypt:
    """Test that decrypted columns are not marked dirty for the next flush."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_decrypt_many_does_not_mark_column_dirty(self):
        user = AutoDecryptUser(id=1, email=wrap_encrypted("a@x.com"))
        state = sa_inspect(user)
        state._commit_all(state.dict)

        assert "email" not in state.committed_state

        asyncio.run(AutoDecryptUser.decrypt_many([user]))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert "email" not in state.committed_state
