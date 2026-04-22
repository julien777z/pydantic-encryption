import asyncio
from typing import Any
from unittest.mock import patch

from sqlalchemy import inspect as sa_inspect, select
from sqlalchemy.orm import DeclarativeBase, Mapped, configure_mappers, mapped_column

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.bulk import (
    _DecryptOnAccessDescriptor,
    _decrypt_column_batch_async,
    _decrypt_column_batch_sync,
    _pending_siblings,
    PENDING_DECRYPT_KEY,
)
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


class _OnAccessBase(DeclarativeBase):
    """Isolated declarative base for on-access decrypt unit tests."""


class _OnAccessContractor(_OnAccessBase, DeferredDecryptMixin):
    """Two encrypted columns to verify per-column batching and scoped decrypts."""

    __tablename__ = "_on_access_contractor"

    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )
    last_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


def _encrypt(value: Any) -> bytes:
    """Encrypt a value via the SQLAlchemyEncryptedValue write path."""

    return SQLAlchemyEncryptedValue().process_bind_param(value, None)


def _wrap(value: Any) -> EncryptedValue:
    """Wrap ciphertext in EncryptedValue the way process_result_value does on read."""

    return EncryptedValue(_encrypt(value))


class TestDescriptorInstallation:
    """Test that the on-access descriptor is installed on every encrypted column."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_encrypted_columns_wrapped_in_descriptor(self):
        for column_key in ("first_name", "last_name"):
            descriptor = _OnAccessContractor.__dict__[column_key]

            assert isinstance(descriptor, _DecryptOnAccessDescriptor)

    def test_non_encrypted_columns_untouched(self):
        assert not isinstance(
            _OnAccessContractor.__dict__["id"], _DecryptOnAccessDescriptor
        )

    def test_class_level_access_returns_instrumented_attribute(self):
        attr = _OnAccessContractor.first_name

        assert not isinstance(attr, _DecryptOnAccessDescriptor)
        assert hasattr(attr, "key")
        assert attr.key == "first_name"

    def test_orm_query_expressions_still_work(self):
        stmt = select(_OnAccessContractor).where(
            _OnAccessContractor.first_name == "Ada"
        )

        compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "first_name" in compiled


class TestAsyncBatchAcrossSiblings:
    """Test that the async batch helper decrypts one column across every row in parallel."""

    def test_batches_across_every_row(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"), last_name=_wrap("Lovelace"))
        b = _OnAccessContractor(id=2, first_name=_wrap("Alan"), last_name=_wrap("Turing"))
        c = _OnAccessContractor(id=3, first_name=_wrap("Grace"), last_name=_wrap("Hopper"))

        asyncio.run(_decrypt_column_batch_async([a, b, c], "first_name"))

        assert sa_inspect(a).dict["first_name"] == "Ada"
        assert sa_inspect(b).dict["first_name"] == "Alan"
        assert sa_inspect(c).dict["first_name"] == "Grace"

        assert isinstance(sa_inspect(a).dict["last_name"], EncryptedValue)
        assert isinstance(sa_inspect(b).dict["last_name"], EncryptedValue)
        assert isinstance(sa_inspect(c).dict["last_name"], EncryptedValue)

    def test_decrypt_call_count_equals_row_count(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"), last_name=_wrap("Lovelace"))
        b = _OnAccessContractor(id=2, first_name=_wrap("Alan"), last_name=_wrap("Turing"))

        call_count = {"n": 0}

        from pydantic_encryption.adapters.encryption.fernet import FernetAdapter

        original_async_decrypt = FernetAdapter.async_decrypt

        async def counting_decrypt(ciphertext, *, key=None):
            call_count["n"] += 1
            return await original_async_decrypt(ciphertext, key=key)

        with patch.object(FernetAdapter, "async_decrypt", side_effect=counting_decrypt):
            asyncio.run(_decrypt_column_batch_async([a, b], "first_name"))

        assert call_count["n"] == 2


class TestSyncFallback:
    """Test that the sync fallback decrypts each row in sequence."""

    def test_sync_fallback_decrypts_every_row(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))
        b = _OnAccessContractor(id=2, first_name=_wrap("Alan"))

        _decrypt_column_batch_sync([a, b], "first_name")

        assert sa_inspect(a).dict["first_name"] == "Ada"
        assert sa_inspect(b).dict["first_name"] == "Alan"

    def test_sync_fallback_noop_when_already_plaintext(self):
        a = _OnAccessContractor(id=1, first_name="Ada")

        _decrypt_column_batch_sync([a], "first_name")

        assert sa_inspect(a).dict["first_name"] == "Ada"


class TestPendingSiblings:
    """Test that _pending_siblings extracts the bucket list for a given class."""

    def test_returns_empty_list_when_session_has_no_bucket(self):
        from types import SimpleNamespace

        session = SimpleNamespace(info={})
        assert _pending_siblings(session, _OnAccessContractor) == []

    def test_returns_instances_when_class_present_in_bucket(self):
        from types import SimpleNamespace
        from collections import defaultdict

        a = _OnAccessContractor(id=1)
        b = _OnAccessContractor(id=2)
        bucket: dict[type, list[Any]] = defaultdict(list)
        bucket[_OnAccessContractor].extend([a, b])
        session = SimpleNamespace(info={PENDING_DECRYPT_KEY: bucket})

        assert _pending_siblings(session, _OnAccessContractor) == [a, b]

    def test_returns_empty_list_when_session_is_none(self):
        assert _pending_siblings(None, _OnAccessContractor) == []


class TestDescriptorReadPath:
    """Test that attribute reads trigger decryption lazily and cache the plaintext."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_first_read_decrypts_subsequent_reads_are_cached(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))

        assert isinstance(sa_inspect(a).dict["first_name"], EncryptedValue)

        assert a.first_name == "Ada"

        assert sa_inspect(a).dict["first_name"] == "Ada"

    def test_second_read_does_not_retrigger_decrypt(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))

        call_count = {"n": 0}

        original_sync = _decrypt_column_batch_sync

        def counting_sync(rows, column_key):
            call_count["n"] += 1
            return original_sync(rows, column_key)

        with patch(
            "pydantic_encryption.integrations.sqlalchemy.bulk._decrypt_column_batch_sync",
            side_effect=counting_sync,
        ):
            _ = a.first_name
            _ = a.first_name
            _ = a.first_name

        assert call_count["n"] == 1

    def test_reading_one_column_leaves_others_encrypted(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"), last_name=_wrap("Lovelace"))

        _ = a.first_name

        assert isinstance(sa_inspect(a).dict["last_name"], EncryptedValue)
