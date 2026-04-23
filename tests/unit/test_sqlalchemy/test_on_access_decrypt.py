import asyncio
from collections import defaultdict
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from weakref import WeakSet

import pytest
from sqlalchemy import inspect as sa_inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin, decrypt_rows
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY, pending_siblings
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue
from tests.factories import UserNameFactory
from tests.models import UserNameFixture


class _OnAccessBase(DeclarativeBase):
    """Isolated declarative base for on-access decrypt unit tests."""


class _OnAccessRow(_OnAccessBase, DeferredDecryptMixin):
    """Two encrypted columns to verify per-column batching and scoped decrypts."""

    __tablename__ = "_on_access_row"

    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )
    last_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


class _OnAccessBytesRow(_OnAccessBase, DeferredDecryptMixin):
    """Bytes-typed encrypted column for coverage of the same descriptor install path."""

    __tablename__ = "_on_access_bytes_row"

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


def _build_row(user: UserNameFixture) -> _OnAccessRow:
    """Build an _OnAccessRow with encrypted first_name / last_name from a UserNameFixture."""

    return _OnAccessRow(
        id=user.id,
        first_name=_wrap(user.first_name),
        last_name=_wrap(user.last_name),
    )


def _build_bytes_row(user: UserNameFixture) -> _OnAccessBytesRow:
    """Build an _OnAccessBytesRow with an encrypted bytes payload from a UserNameFixture."""

    return _OnAccessBytesRow(id=user.id, payload=_wrap(user.payload))


@pytest.fixture
def user_fixture() -> UserNameFixture:
    """A single faker-backed user with name parts and a bytes payload."""

    return UserNameFactory.build()


@pytest.fixture
def other_user_fixture() -> UserNameFixture:
    """A second faker-backed user distinct from user_fixture."""

    return UserNameFactory.build()


@pytest.fixture
def users_batch() -> list[UserNameFixture]:
    """A batch of faker-backed users for multi-row scenarios."""

    return UserNameFactory.batch(3)


class TestDescriptorInstallation:
    """Test that the on-access descriptor is installed on every encrypted column."""

    @classmethod
    def setup_class(cls):
        """Configure mappers before running tests in this class."""

        configure_mappers()

    def test_encrypted_columns_wrapped_in_descriptor(self):
        """Test that each encrypted column is wrapped in the on-access descriptor."""

        for column_key in ("first_name", "last_name"):
            descriptor = _OnAccessRow.__dict__[column_key]

            assert isinstance(descriptor, DecryptOnAccessDescriptor)

    def test_non_encrypted_columns_untouched(self):
        """Test that non-encrypted columns keep their default SA attribute."""

        assert not isinstance(_OnAccessRow.__dict__["id"], DecryptOnAccessDescriptor)

    def test_class_level_access_returns_instrumented_attribute(self):
        """Test that class-level attribute access returns the SA InstrumentedAttribute."""

        attr = _OnAccessRow.first_name

        assert not isinstance(attr, DecryptOnAccessDescriptor)
        assert hasattr(attr, "key")
        assert attr.key == "first_name"

    def test_orm_query_expressions_still_work(self, user_fixture: UserNameFixture):
        """Test that ORM query expressions still compile against encrypted columns."""

        stmt = select(_OnAccessRow).where(_OnAccessRow.first_name == user_fixture.first_name)

        compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "first_name" in compiled

    def test_descriptor_set_delegates_to_wrapped(self, user_fixture: UserNameFixture):
        """Test that assigning through the descriptor stores on SA state."""

        row = _OnAccessRow(id=user_fixture.id)

        row.first_name = user_fixture.first_name

        assert sa_inspect(row).dict["first_name"] == user_fixture.first_name

    def test_descriptor_delete_delegates_to_wrapped(self, user_fixture: UserNameFixture):
        """Test that deleting through the descriptor removes the column from SA state."""

        row = _build_row(user_fixture)

        del row.first_name

        assert "first_name" not in sa_inspect(row).dict

    def test_descriptor_exposes_wrapped_key(self):
        """Test that the descriptor exposes the wrapped attribute's column key."""

        descriptor = _OnAccessRow.__dict__["first_name"]

        assert descriptor.key == "first_name"


class TestBatchAcrossSiblings:
    """Test that the async batch helper decrypts one column across every row in parallel."""

    def test_batches_across_every_row(self, users_batch: list[UserNameFixture]):
        """Test that batch-decrypt touches only the requested column across all rows."""

        rows = [_build_row(user) for user in users_batch]

        asyncio.run(decrypt_rows(rows, "first_name"))

        for row, user in zip(rows, users_batch):
            assert sa_inspect(row).dict["first_name"] == user.first_name
            assert isinstance(sa_inspect(row).dict["last_name"], EncryptedValue)

    def test_skips_rows_whose_column_is_already_decrypted(
        self, user_fixture: UserNameFixture, other_user_fixture: UserNameFixture,
    ):
        """Test that already-decrypted bytes-typed columns are not re-decrypted."""

        row_a = _build_bytes_row(user_fixture)
        row_b = _build_bytes_row(other_user_fixture)

        asyncio.run(decrypt_rows([row_a], "payload"))

        assert sa_inspect(row_a).dict["payload"] == user_fixture.payload

        asyncio.run(decrypt_rows([row_a, row_b], "payload"))

        assert sa_inspect(row_a).dict["payload"] == user_fixture.payload
        assert sa_inspect(row_b).dict["payload"] == other_user_fixture.payload

    def test_decrypt_call_count_equals_row_count(
        self, user_fixture: UserNameFixture, other_user_fixture: UserNameFixture,
    ):
        """Test that one decrypt call is issued per row in the batch."""

        rows = [_build_row(user_fixture), _build_row(other_user_fixture)]

        call_count = {"n": 0}

        from pydantic_encryption.adapters.encryption.fernet import FernetAdapter

        original_async_decrypt = FernetAdapter.async_decrypt

        async def counting_decrypt(ciphertext, *, key=None):
            call_count["n"] += 1
            return await original_async_decrypt(ciphertext, key=key)

        with patch.object(FernetAdapter, "async_decrypt", side_effect=counting_decrypt):
            asyncio.run(decrypt_rows(rows, "first_name"))

        assert call_count["n"] == 2


class TestPendingSiblings:
    """Test that pending_siblings extracts the bucket list for a given class."""

    def test_returns_empty_list_when_session_has_no_bucket(self):
        """Test that pending_siblings returns an empty list for a fresh session."""

        session = SimpleNamespace(info={})
        assert pending_siblings(session, _OnAccessRow) == []

    def test_returns_instances_when_class_present_in_bucket(
        self, user_fixture: UserNameFixture, other_user_fixture: UserNameFixture,
    ):
        """Test that pending_siblings returns registered instances for a class."""

        row_a = _OnAccessRow(id=user_fixture.id)
        row_b = _OnAccessRow(id=other_user_fixture.id)
        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[_OnAccessRow].add(row_a)
        bucket[_OnAccessRow].add(row_b)
        session = SimpleNamespace(info={PENDING_DECRYPT_KEY: bucket})

        siblings = pending_siblings(session, _OnAccessRow)
        assert set(siblings) == {row_a, row_b}

    def test_returns_empty_list_when_session_is_none(self):
        """Test that pending_siblings returns an empty list when session is None."""

        assert pending_siblings(None, _OnAccessRow) == []


class TestDescriptorOnDetachedRead:
    """Test that reading an encrypted attribute on a detached instance decrypts in place."""

    @classmethod
    def setup_class(cls):
        """Configure mappers before running tests in this class."""

        configure_mappers()

    def test_detached_instance_decrypts_in_place(self, user_fixture: UserNameFixture):
        """Test that reading an encrypted column on a detached instance returns plaintext."""

        row = _build_row(user_fixture)

        assert row.first_name == user_fixture.first_name
        assert sa_inspect(row).dict["first_name"] == user_fixture.first_name

    def test_detached_read_does_not_decrypt_other_columns(self, user_fixture: UserNameFixture):
        """Test that reading one column on a detached row does not eagerly decrypt siblings."""

        row = _build_row(user_fixture)

        assert row.first_name == user_fixture.first_name
        assert isinstance(sa_inspect(row).dict["last_name"], EncryptedValue)

    def test_other_columns_still_readable_when_plaintext(self, user_fixture: UserNameFixture):
        """Test that plaintext values on a detached row read back unchanged."""

        row = _OnAccessRow(id=user_fixture.id, first_name=user_fixture.first_name, last_name=None)

        assert row.first_name == user_fixture.first_name
        assert row.last_name is None

    def test_plain_integer_columns_never_raise(self, user_fixture: UserNameFixture):
        """Test that non-encrypted columns are readable on a detached row."""

        row = _OnAccessRow(id=user_fixture.id)

        assert row.id == user_fixture.id

    def test_no_greenlet_falls_back_to_sync_decrypt(self, user_fixture: UserNameFixture):
        """Test that a session-bound row outside a greenlet falls back to sync decrypt."""

        row = _build_row(user_fixture)
        fake_session = SimpleNamespace(info={})

        with patch(
            "pydantic_encryption.integrations.sqlalchemy.descriptor.object_session",
            return_value=fake_session,
        ):
            assert row.first_name == user_fixture.first_name

    def test_decrypt_method_unblocks_subsequent_reads(self, user_fixture: UserNameFixture):
        """Test that awaiting instance.decrypt() leaves the attribute as plaintext."""

        row = _build_row(user_fixture)

        asyncio.run(row.decrypt())

        assert row.first_name == user_fixture.first_name
