import asyncio
import importlib
from collections import defaultdict
from types import SimpleNamespace
from typing import Any
from weakref import WeakSet

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

import pydantic_encryption
from pydantic_encryption.integrations.sqlalchemy import finalize_session
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from pydantic_encryption.types import EncryptedValue


class _FinalizeBase(DeclarativeBase):
    """Isolated declarative base for finalize_session tests."""


class _FinalizeUser(_FinalizeBase):
    """Mapped class with one deferred encrypted column."""

    __tablename__ = "_finalize_user"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


def _wrap(value: Any) -> EncryptedValue:
    """Wrap ciphertext in EncryptedValue the way process_result_value does on read."""

    return EncryptedValue(SQLAlchemyEncryptedValue().process_bind_param(value, None))


class _FakeAsyncSession(SimpleNamespace):
    """Minimal AsyncSession stand-in exposing the surface finalize_session uses."""

    def __init__(self, in_transaction: bool) -> None:
        super().__init__(info={}, commit_calls=0, _in_tx=in_transaction)

    def in_transaction(self) -> bool:
        return self._in_tx

    async def commit(self) -> None:
        self.commit_calls += 1
        self._in_tx = False


class TestFinalizeSession:
    """Test the finalize_session helper that drains pending decrypts and commits."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_drains_pending_and_commits_when_in_transaction(self):
        session = _FakeAsyncSession(in_transaction=True)
        user = _FinalizeUser(id=1, email=_wrap("a@x.com"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[_FinalizeUser].add(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(finalize_session(session))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert PENDING_DECRYPT_KEY not in session.info
        assert session.commit_calls == 1

    def test_skips_commit_when_not_in_transaction(self):
        session = _FakeAsyncSession(in_transaction=False)

        asyncio.run(finalize_session(session))

        assert session.commit_calls == 0

    def test_drains_pending_without_commit_when_not_in_transaction(self):
        session = _FakeAsyncSession(in_transaction=False)
        user = _FinalizeUser(id=1, email=_wrap("b@x.com"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[_FinalizeUser].add(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(finalize_session(session))

        assert sa_inspect(user).dict["email"] == "b@x.com"
        assert PENDING_DECRYPT_KEY not in session.info
        assert session.commit_calls == 0


class TestFinalizeSessionLazyImport:
    """Test that finalize_session is re-exported from the top-level package via __getattr__."""

    def test_top_level_attribute_resolves_to_helper(self):
        # Force the lazy import branch by popping any cached reference and
        # re-fetching through __getattr__.
        cached = getattr(pydantic_encryption, "__dict__", {}).pop("finalize_session", None)
        try:
            resolved = pydantic_encryption.finalize_session
        finally:
            if cached is not None:
                pydantic_encryption.__dict__["finalize_session"] = cached

        assert resolved is finalize_session

    def test_top_level_attribute_listed_in_all(self):
        module = importlib.import_module("pydantic_encryption")
        assert "finalize_session" in module.__all__
