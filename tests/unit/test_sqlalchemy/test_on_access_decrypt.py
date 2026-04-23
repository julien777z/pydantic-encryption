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


@pytest.fixture
def sample_a() -> str:
    """Sample plaintext A used across tests."""

    return "sample-a"


@pytest.fixture
def sample_b() -> str:
    """Sample plaintext B used across tests."""

    return "sample-b"


@pytest.fixture
def sample_c() -> str:
    """Sample plaintext C used across tests."""

    return "sample-c"


@pytest.fixture
def sample_d() -> str:
    """Sample plaintext D used across tests."""

    return "sample-d"


@pytest.fixture
def sample_e() -> str:
    """Sample plaintext E used across tests."""

    return "sample-e"


@pytest.fixture
def sample_f() -> str:
    """Sample plaintext F used across tests."""

    return "sample-f"


@pytest.fixture
def sample_bytes_a() -> bytes:
    """Sample bytes payload A used across tests."""

    return b"payload-a"


@pytest.fixture
def sample_bytes_b() -> bytes:
    """Sample bytes payload B used across tests."""

    return b"payload-b"


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

    def test_orm_query_expressions_still_work(self, sample_a: str):
        """Test that ORM query expressions still compile against encrypted columns."""

        stmt = select(_OnAccessRow).where(_OnAccessRow.first_name == sample_a)

        compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "first_name" in compiled

    def test_descriptor_set_delegates_to_wrapped(self, sample_a: str):
        """Test that assigning through the descriptor stores on SA state."""

        row = _OnAccessRow(id=1)

        row.first_name = sample_a

        assert sa_inspect(row).dict["first_name"] == sample_a

    def test_descriptor_delete_delegates_to_wrapped(self, sample_a: str):
        """Test that deleting through the descriptor removes the column from SA state."""

        row = _OnAccessRow(id=1, first_name=_wrap(sample_a))

        del row.first_name

        assert "first_name" not in sa_inspect(row).dict

    def test_descriptor_exposes_wrapped_key(self):
        """Test that the descriptor exposes the wrapped attribute's column key."""

        descriptor = _OnAccessRow.__dict__["first_name"]

        assert descriptor.key == "first_name"


class TestBatchAcrossSiblings:
    """Test that the async batch helper decrypts one column across every row in parallel."""

    def test_batches_across_every_row(
        self,
        sample_a: str,
        sample_b: str,
        sample_c: str,
        sample_d: str,
        sample_e: str,
        sample_f: str,
    ):
        """Test that batch-decrypt touches only the requested column across all rows."""

        row_a = _OnAccessRow(id=1, first_name=_wrap(sample_a), last_name=_wrap(sample_b))
        row_b = _OnAccessRow(id=2, first_name=_wrap(sample_c), last_name=_wrap(sample_d))
        row_c = _OnAccessRow(id=3, first_name=_wrap(sample_e), last_name=_wrap(sample_f))

        asyncio.run(decrypt_rows([row_a, row_b, row_c], "first_name"))

        assert sa_inspect(row_a).dict["first_name"] == sample_a
        assert sa_inspect(row_b).dict["first_name"] == sample_c
        assert sa_inspect(row_c).dict["first_name"] == sample_e

        assert isinstance(sa_inspect(row_a).dict["last_name"], EncryptedValue)
        assert isinstance(sa_inspect(row_b).dict["last_name"], EncryptedValue)
        assert isinstance(sa_inspect(row_c).dict["last_name"], EncryptedValue)

    def test_skips_rows_whose_column_is_already_decrypted(
        self, sample_bytes_a: bytes, sample_bytes_b: bytes,
    ):
        """Test that already-decrypted bytes-typed columns are not re-decrypted."""

        row_a = _OnAccessBytesRow(id=1, payload=_wrap(sample_bytes_a))
        row_b = _OnAccessBytesRow(id=2, payload=_wrap(sample_bytes_b))

        asyncio.run(decrypt_rows([row_a], "payload"))

        assert sa_inspect(row_a).dict["payload"] == sample_bytes_a

        asyncio.run(decrypt_rows([row_a, row_b], "payload"))

        assert sa_inspect(row_a).dict["payload"] == sample_bytes_a
        assert sa_inspect(row_b).dict["payload"] == sample_bytes_b

    def test_decrypt_call_count_equals_row_count(
        self, sample_a: str, sample_b: str, sample_c: str, sample_d: str,
    ):
        """Test that one decrypt call is issued per row in the batch."""

        row_a = _OnAccessRow(id=1, first_name=_wrap(sample_a), last_name=_wrap(sample_b))
        row_b = _OnAccessRow(id=2, first_name=_wrap(sample_c), last_name=_wrap(sample_d))

        call_count = {"n": 0}

        from pydantic_encryption.adapters.encryption.fernet import FernetAdapter

        original_async_decrypt = FernetAdapter.async_decrypt

        async def counting_decrypt(ciphertext, *, key=None):
            call_count["n"] += 1
            return await original_async_decrypt(ciphertext, key=key)

        with patch.object(FernetAdapter, "async_decrypt", side_effect=counting_decrypt):
            asyncio.run(decrypt_rows([row_a, row_b], "first_name"))

        assert call_count["n"] == 2


class TestPendingSiblings:
    """Test that pending_siblings extracts the bucket list for a given class."""

    def test_returns_empty_list_when_session_has_no_bucket(self):
        """Test that pending_siblings returns an empty list for a fresh session."""

        session = SimpleNamespace(info={})
        assert pending_siblings(session, _OnAccessRow) == []

    def test_returns_instances_when_class_present_in_bucket(self):
        """Test that pending_siblings returns registered instances for a class."""

        row_a = _OnAccessRow(id=1)
        row_b = _OnAccessRow(id=2)
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

    def test_detached_instance_decrypts_in_place(self, sample_a: str):
        """Test that reading an encrypted column on a detached instance returns plaintext."""

        row = _OnAccessRow(id=1, first_name=_wrap(sample_a))

        assert row.first_name == sample_a
        assert sa_inspect(row).dict["first_name"] == sample_a

    def test_detached_read_does_not_decrypt_other_columns(
        self, sample_a: str, sample_b: str,
    ):
        """Test that reading one column on a detached row does not eagerly decrypt siblings."""

        row = _OnAccessRow(id=1, first_name=_wrap(sample_a), last_name=_wrap(sample_b))

        assert row.first_name == sample_a
        assert isinstance(sa_inspect(row).dict["last_name"], EncryptedValue)

    def test_other_columns_still_readable_when_plaintext(self, sample_a: str):
        """Test that plaintext values on a detached row read back unchanged."""

        row = _OnAccessRow(id=1, first_name=sample_a, last_name=None)

        assert row.first_name == sample_a
        assert row.last_name is None

    def test_plain_integer_columns_never_raise(self):
        """Test that non-encrypted columns are readable on a detached row."""

        row = _OnAccessRow(id=42)

        assert row.id == 42

    def test_no_greenlet_falls_back_to_sync_decrypt(self, sample_a: str):
        """Test that a session-bound row outside a greenlet falls back to sync decrypt."""

        row = _OnAccessRow(id=1, first_name=_wrap(sample_a))
        fake_session = SimpleNamespace(info={})

        with patch(
            "pydantic_encryption.integrations.sqlalchemy.descriptor.object_session",
            return_value=fake_session,
        ):
            assert row.first_name == sample_a

    def test_decrypt_method_unblocks_subsequent_reads(self, sample_a: str):
        """Test that awaiting instance.decrypt() leaves the attribute as plaintext."""

        row = _OnAccessRow(id=1, first_name=_wrap(sample_a))

        asyncio.run(row.decrypt())

        assert row.first_name == sample_a
