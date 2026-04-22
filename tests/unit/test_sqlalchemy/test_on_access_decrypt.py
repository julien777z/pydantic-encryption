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
from pydantic_encryption.types import EncryptedValue, EncryptedValueAccessError


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


class TestDescriptorInstallation:
    """Test that the on-access descriptor is installed on every encrypted column."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_encrypted_columns_wrapped_in_descriptor(self):
        for column_key in ("first_name", "last_name"):
            descriptor = _OnAccessContractor.__dict__[column_key]

            assert isinstance(descriptor, DecryptOnAccessDescriptor)

    def test_non_encrypted_columns_untouched(self):
        assert not isinstance(_OnAccessContractor.__dict__["id"], DecryptOnAccessDescriptor)

    def test_class_level_access_returns_instrumented_attribute(self):
        attr = _OnAccessContractor.first_name

        assert not isinstance(attr, DecryptOnAccessDescriptor)
        assert hasattr(attr, "key")
        assert attr.key == "first_name"

    def test_orm_query_expressions_still_work(self):
        stmt = select(_OnAccessContractor).where(_OnAccessContractor.first_name == "Ada")

        compiled = str(stmt.compile(compile_kwargs={"literal_binds": False}))
        assert "first_name" in compiled

    def test_descriptor_set_delegates_to_wrapped(self):
        a = _OnAccessContractor(id=1)

        a.first_name = "Grace"

        assert sa_inspect(a).dict["first_name"] == "Grace"

    def test_descriptor_delete_delegates_to_wrapped(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))

        del a.first_name

        assert "first_name" not in sa_inspect(a).dict

    def test_descriptor_exposes_wrapped_key(self):
        descriptor = _OnAccessContractor.__dict__["first_name"]

        assert descriptor.key == "first_name"


class TestBatchAcrossSiblings:
    """Test that the async batch helper decrypts one column across every row in parallel."""

    def test_batches_across_every_row(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"), last_name=_wrap("Lovelace"))
        b = _OnAccessContractor(id=2, first_name=_wrap("Alan"), last_name=_wrap("Turing"))
        c = _OnAccessContractor(id=3, first_name=_wrap("Grace"), last_name=_wrap("Hopper"))

        asyncio.run(decrypt_rows([a, b, c], "first_name"))

        assert sa_inspect(a).dict["first_name"] == "Ada"
        assert sa_inspect(b).dict["first_name"] == "Alan"
        assert sa_inspect(c).dict["first_name"] == "Grace"

        assert isinstance(sa_inspect(a).dict["last_name"], EncryptedValue)
        assert isinstance(sa_inspect(b).dict["last_name"], EncryptedValue)
        assert isinstance(sa_inspect(c).dict["last_name"], EncryptedValue)

    def test_skips_rows_whose_column_is_already_decrypted(self):
        """Decrypted bytes-typed columns look like plain bytes; must not be re-decrypted."""

        a = _OnAccessBytesRow(id=1, payload=_wrap(b"secret-a"))
        b = _OnAccessBytesRow(id=2, payload=_wrap(b"secret-b"))

        asyncio.run(decrypt_rows([a], "payload"))

        assert sa_inspect(a).dict["payload"] == b"secret-a"

        asyncio.run(decrypt_rows([a, b], "payload"))

        assert sa_inspect(a).dict["payload"] == b"secret-a"
        assert sa_inspect(b).dict["payload"] == b"secret-b"

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
            asyncio.run(decrypt_rows([a, b], "first_name"))

        assert call_count["n"] == 2


class TestPendingSiblings:
    """Test that pending_siblings extracts the bucket list for a given class."""

    def test_returns_empty_list_when_session_has_no_bucket(self):
        session = SimpleNamespace(info={})
        assert pending_siblings(session, _OnAccessContractor) == []

    def test_returns_instances_when_class_present_in_bucket(self):
        a = _OnAccessContractor(id=1)
        b = _OnAccessContractor(id=2)
        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[_OnAccessContractor].add(a)
        bucket[_OnAccessContractor].add(b)
        session = SimpleNamespace(info={PENDING_DECRYPT_KEY: bucket})

        siblings = pending_siblings(session, _OnAccessContractor)
        assert set(siblings) == {a, b}

    def test_returns_empty_list_when_session_is_none(self):
        assert pending_siblings(None, _OnAccessContractor) == []


class TestDescriptorRaisesOnDetachedRead:
    """Test that reading an encrypted attribute on a detached instance always raises."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_detached_instance_raises_access_error(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))

        with pytest.raises(EncryptedValueAccessError) as exc_info:
            _ = a.first_name

        message = str(exc_info.value)
        assert "_OnAccessContractor" in message
        assert "first_name" in message
        assert "detached" in message.lower()

    def test_other_columns_still_readable_when_plaintext(self):
        a = _OnAccessContractor(id=1, first_name="plain", last_name=None)

        assert a.first_name == "plain"
        assert a.last_name is None

    def test_plain_integer_columns_never_raise(self):
        a = _OnAccessContractor(id=42)

        assert a.id == 42

    def test_no_greenlet_falls_back_to_sync_decrypt(self):
        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))
        fake_session = SimpleNamespace(info={})

        with patch(
            "pydantic_encryption.integrations.sqlalchemy.descriptor.object_session",
            return_value=fake_session,
        ):
            assert a.first_name == "Ada"

    def test_decrypt_method_unblocks_subsequent_reads(self):
        """After awaiting instance.decrypt(), the attribute reads return plaintext."""

        a = _OnAccessContractor(id=1, first_name=_wrap("Ada"))

        asyncio.run(a.decrypt())

        assert a.first_name == "Ada"
