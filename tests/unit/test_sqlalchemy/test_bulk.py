import asyncio
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin, async_decrypt_rows
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


class TestDeferDecrypt:
    """Test that defer_decrypt=True skips decryption on the read path."""

    def test_defer_decrypt_returns_encrypted_value(self):
        adapter = SQLAlchemyEncryptedValue(defer_decrypt=True)
        ciphertext = adapter.process_bind_param("hello", None)
        assert ciphertext is not None

        result = adapter.process_result_value(ciphertext, None)
        assert isinstance(result, EncryptedValue)
        # defer_decrypt must NOT return plaintext
        assert result != "hello"

    def test_defer_decrypt_none_passthrough(self):
        adapter = SQLAlchemyEncryptedValue(defer_decrypt=True)
        assert adapter.process_result_value(None, None) is None

    def test_default_decrypt_returns_plaintext(self):
        adapter = SQLAlchemyEncryptedValue()
        ciphertext = adapter.process_bind_param("hello", None)
        result = adapter.process_result_value(ciphertext, None)
        assert result == "hello"


class TestAsyncDecryptRows:
    """Test the async_decrypt_rows bulk helper."""

    def _make_ciphertext(self, value):
        return SQLAlchemyEncryptedValue(defer_decrypt=False).process_bind_param(value, None)

    def test_async_decrypt_rows_fernet(self):
        # Build 3 fake rows with 2 encrypted columns each.
        rows = [
            SimpleNamespace(
                email=EncryptedValue(self._make_ciphertext(f"user{i}@example.com")),
                secret=EncryptedValue(self._make_ciphertext(f"secret-{i}")),
            )
            for i in range(3)
        ]

        asyncio.run(async_decrypt_rows(rows, "email", "secret"))

        for i, row in enumerate(rows):
            assert row.email == f"user{i}@example.com"
            assert row.secret == f"secret-{i}"

    def test_async_decrypt_rows_empty(self):
        asyncio.run(async_decrypt_rows([], "email"))  # no error
        asyncio.run(async_decrypt_rows([SimpleNamespace(email=None)], "email"))  # no error

    def test_async_decrypt_rows_skips_none_cells(self):
        rows = [
            SimpleNamespace(email=EncryptedValue(self._make_ciphertext("a@x.com")), secret=None),
            SimpleNamespace(email=None, secret=EncryptedValue(self._make_ciphertext("s1"))),
        ]

        asyncio.run(async_decrypt_rows(rows, "email", "secret"))

        assert rows[0].email == "a@x.com"
        assert rows[0].secret is None
        assert rows[1].email is None
        assert rows[1].secret == "s1"

    def test_async_decrypt_rows_respects_concurrency(self):
        rows = [
            SimpleNamespace(email=EncryptedValue(self._make_ciphertext(f"u{i}@x.com")))
            for i in range(5)
        ]

        asyncio.run(async_decrypt_rows(rows, "email", concurrency=2))

        for i, row in enumerate(rows):
            assert row.email == f"u{i}@x.com"


class _BulkBase(DeclarativeBase):
    """Isolated declarative base for DeferredDecryptMixin tests."""


class _BulkOrg(_BulkBase, DeferredDecryptMixin):
    """Test ORM parent with no encrypted columns."""

    __tablename__ = "_bulk_test_org"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str | None] = mapped_column(nullable=True, default=None)
    contractors: Mapped[list["_BulkContractor"]] = relationship(back_populates="org")


class _BulkContractor(_BulkBase, DeferredDecryptMixin):
    """Test ORM child with deferred encrypted columns."""

    __tablename__ = "_bulk_test_contractor"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("_bulk_test_org.id"), nullable=True, default=None)
    first_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(defer_decrypt=True), nullable=True, default=None
    )
    last_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue(defer_decrypt=True), nullable=True, default=None
    )
    org: Mapped["_BulkOrg | None"] = relationship(back_populates="contractors")


def _encrypt_deferred(value: str) -> bytes:
    """Encrypt a value using the non-deferred SQLAlchemyEncryptedValue on the write path."""

    return SQLAlchemyEncryptedValue(defer_decrypt=False).process_bind_param(value, None)


class TestDeferredDecryptMixin:
    """Test the DeferredDecryptMixin decrypt() and decrypt_many() helpers."""

    def test_decrypt_many_none_and_empty(self):
        asyncio.run(_BulkContractor.decrypt_many(None))
        asyncio.run(_BulkContractor.decrypt_many([]))

    def test_instance_decrypt(self):
        contractor = _BulkContractor(
            id=1,
            first_name=_encrypt_deferred("Alice"),
            last_name=_encrypt_deferred("Smith"),
        )

        returned = asyncio.run(contractor.decrypt())

        assert returned is contractor
        assert contractor.first_name == "Alice"
        assert contractor.last_name == "Smith"

    def test_decrypt_many(self):
        contractors = [
            _BulkContractor(
                id=i,
                first_name=_encrypt_deferred(f"First{i}"),
                last_name=_encrypt_deferred(f"Last{i}"),
            )
            for i in range(3)
        ]

        asyncio.run(_BulkContractor.decrypt_many(contractors))

        for i, contractor in enumerate(contractors):
            assert contractor.first_name == f"First{i}"
            assert contractor.last_name == f"Last{i}"

    def test_none_column_values_skipped(self):
        contractor = _BulkContractor(id=1, first_name=_encrypt_deferred("Alice"), last_name=None)

        asyncio.run(contractor.decrypt())

        assert contractor.first_name == "Alice"
        assert contractor.last_name is None

    def test_walks_loaded_relationships(self):
        org = _BulkOrg(id=1, name="Acme")
        contractor = _BulkContractor(id=1, first_name=_encrypt_deferred("Alice"), last_name=None)
        org.contractors = [contractor]

        asyncio.run(org.decrypt())

        assert contractor.first_name == "Alice"

    def test_all_columns_none(self):
        contractor = _BulkContractor(id=1, first_name=None, last_name=None)

        asyncio.run(contractor.decrypt())

        assert contractor.first_name is None
        assert contractor.last_name is None


class TestDeferredDecryptScalarHelpers:
    """Test the scalar_one_or_none and scalars_all query helpers on DeferredDecryptMixin."""

    def _make_session_stub(self, returned: Any) -> Any:
        """Return a minimal async session stub whose execute() returns a fake Result."""

        class _Result:
            def __init__(self, value):
                self._value = value

            def scalar_one_or_none(self):
                return self._value if not isinstance(self._value, list) else None

            def scalars(self):
                rows = self._value if isinstance(self._value, list) else []

                class _Scalars:
                    def __init__(self, rows):
                        self._rows = rows

                    def all(self):
                        return list(self._rows)

                return _Scalars(rows)

        class _Session:
            def __init__(self, value):
                self._value = value

            async def execute(self, _stmt):
                return _Result(self._value)

        return _Session(returned)

    def test_scalar_one_or_none_decrypts(self):
        contractor = _BulkContractor(id=1, first_name=_encrypt_deferred("Alice"))
        session = self._make_session_stub(contractor)

        result = asyncio.run(_BulkContractor.scalar_one_or_none(session, object()))

        assert result is contractor
        assert contractor.first_name == "Alice"

    def test_scalar_one_or_none_handles_missing(self):
        session = self._make_session_stub(None)

        result = asyncio.run(_BulkContractor.scalar_one_or_none(session, object()))

        assert result is None

    def test_scalars_all_decrypts(self):
        contractors = [
            _BulkContractor(id=i, first_name=_encrypt_deferred(f"First{i}")) for i in range(3)
        ]
        session = self._make_session_stub(contractors)

        result = asyncio.run(_BulkContractor.scalars_all(session, object()))

        assert result == contractors
        for i, c in enumerate(result):
            assert c.first_name == f"First{i}"

    def test_scalars_all_empty(self):
        session = self._make_session_stub([])

        result = asyncio.run(_BulkContractor.scalars_all(session, object()))

        assert result == []
