import asyncio

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import ForeignKey
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    configure_mappers,
    mapped_column,
    relationship,
)

from pydantic_encryption.integrations.sqlalchemy import (
    DeferredDecryptMixin,
    decrypt_rows,
    decrypt_values,
)
from pydantic_encryption.integrations.sqlalchemy.bulk import column_context
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class DeferBase(DeclarativeBase):
    """Isolated declarative base for mixin auto-defer tests."""


class DeferMixed(DeferBase, DeferredDecryptMixin):
    """Mapped class that inherits DeferredDecryptMixin."""

    __tablename__ = "_defer_mixed"

    id: Mapped[int] = mapped_column(primary_key=True)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue("_defer_mixed.secret"), nullable=True, default=None
    )


class DeferPlain(DeferBase):
    """Mapped class that does NOT inherit DeferredDecryptMixin."""

    __tablename__ = "_defer_plain"

    id: Mapped[int] = mapped_column(primary_key=True)
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue("_defer_plain.secret"), nullable=True, default=None
    )


class DeferPair(DeferBase, DeferredDecryptMixin):
    """Mapped class with two encrypted columns for the row-level bulk helpers."""

    __tablename__ = "_defer_pair"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue("_defer_pair.email"), nullable=True, default=None
    )
    secret: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue("_defer_pair.secret"), nullable=True, default=None
    )


class TestDeferDecrypt:
    """Test that DeferredDecryptMixin auto-defers encrypted columns on the read path."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_mixin_column_returns_encrypted_value(self):
        column_type = DeferMixed.__table__.c.secret.type
        assert column_type._deferred is True

        ciphertext = column_type.process_bind_param("hello", None)
        assert ciphertext is not None

        result = column_type.process_result_value(ciphertext, None)
        assert isinstance(result, EncryptedValue)
        assert result != "hello"

    def test_mixin_column_none_passthrough(self):
        column_type = DeferMixed.__table__.c.secret.type
        assert column_type.process_result_value(None, None) is None

    def test_plain_column_returns_plaintext(self):
        column_type = DeferPlain.__table__.c.secret.type
        assert column_type._deferred is False

        ciphertext = column_type.process_bind_param("hello", None)
        result = column_type.process_result_value(ciphertext, None)
        assert result == "hello"


class TestDecryptRows:
    """Test the decrypt_rows bulk helper."""

    def make_row(self, email: str | None, secret: str | None) -> DeferPair:
        """Build a row whose cells hold ciphertext bound to their own columns."""

        return DeferPair(
            email=None if email is None else encrypt_through_column(DeferPair.__table__.c.email, email),
            secret=None if secret is None else encrypt_through_column(DeferPair.__table__.c.secret, secret),
        )

    def test_decrypt_rows_across_columns(self):
        rows = [self.make_row(f"user{i}@example.com", f"secret-{i}") for i in range(3)]

        asyncio.run(decrypt_rows(rows, "email", "secret"))

        for i, row in enumerate(rows):
            assert row.email == f"user{i}@example.com"
            assert row.secret == f"secret-{i}"

    def test_decrypt_rows_empty(self):
        asyncio.run(decrypt_rows([], "email"))  # no error
        asyncio.run(decrypt_rows([self.make_row(None, None)], "email"))  # no error

    def test_decrypt_rows_skips_none_cells(self):
        rows = [self.make_row("a@x.com", None), self.make_row(None, "s1")]

        asyncio.run(decrypt_rows(rows, "email", "secret"))

        assert rows[0].email == "a@x.com"
        assert rows[0].secret is None
        assert rows[1].email is None
        assert rows[1].secret == "s1"


class ArrayRow(DeferBase):
    """Mapped class with an encrypted array column."""

    __tablename__ = "_array_row"

    id: Mapped[int] = mapped_column(primary_key=True)
    tags: Mapped[list[str] | None] = mapped_column(
        SQLAlchemyPGEncryptedArray("_array_row.tags"), nullable=True, default=None
    )


class BulkBase(DeclarativeBase):
    """Isolated declarative base for DeferredDecryptMixin tests."""


class BulkOrg(BulkBase, DeferredDecryptMixin):
    """Test ORM parent with no encrypted columns."""

    __tablename__ = "_bulk_test_org"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str | None] = mapped_column(nullable=True, default=None)
    contractors: Mapped[list["BulkContractor"]] = relationship(back_populates="org")


class BulkContractor(BulkBase, DeferredDecryptMixin):
    """Test ORM child with deferred encrypted columns."""

    __tablename__ = "_bulk_test_contractor"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int | None] = mapped_column(ForeignKey("_bulk_test_org.id"), nullable=True, default=None)
    first_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue("_bulk_test_contractor.first_name"), nullable=True, default=None
    )
    last_name: Mapped[str | None] = mapped_column(
        SQLAlchemyEncryptedValue("_bulk_test_contractor.last_name"), nullable=True, default=None
    )
    org: Mapped["BulkOrg | None"] = relationship(back_populates="contractors")


def encrypt_first_name(value: str) -> bytes:
    """Encrypt a contractor first name through its own column."""

    return encrypt_through_column(BulkContractor.__table__.c.first_name, value)


def encrypt_last_name(value: str) -> bytes:
    """Encrypt a contractor last name through its own column."""

    return encrypt_through_column(BulkContractor.__table__.c.last_name, value)


class TestDeferredDecryptMixin:
    """Test the DeferredDecryptMixin decrypt() and decrypt_many() helpers."""

    def test_decrypt_many_none_and_empty(self):
        asyncio.run(BulkContractor.decrypt_many(None))
        asyncio.run(BulkContractor.decrypt_many([]))

    def test_instance_decrypt(self):
        contractor = BulkContractor(
            id=1,
            first_name=encrypt_first_name("first"),
            last_name=encrypt_last_name("last"),
        )

        returned = asyncio.run(contractor.decrypt())

        assert returned is contractor
        assert contractor.first_name == "first"
        assert contractor.last_name == "last"

    def test_decrypt_many(self):
        contractors = [
            BulkContractor(
                id=i,
                first_name=encrypt_first_name(f"First{i}"),
                last_name=encrypt_last_name(f"Last{i}"),
            )
            for i in range(3)
        ]

        asyncio.run(BulkContractor.decrypt_many(contractors))

        for i, contractor in enumerate(contractors):
            assert contractor.first_name == f"First{i}"
            assert contractor.last_name == f"Last{i}"

    def test_decrypt_many_accepts_generator(self):
        contractors = [
            BulkContractor(
                id=i,
                first_name=encrypt_first_name(f"Gen{i}"),
                last_name=encrypt_last_name(f"Last{i}"),
            )
            for i in range(3)
        ]

        asyncio.run(BulkContractor.decrypt_many(c for c in contractors))

        for i, contractor in enumerate(contractors):
            assert contractor.first_name == f"Gen{i}"
            assert contractor.last_name == f"Last{i}"

    def test_none_column_values_skipped(self):
        contractor = BulkContractor(id=1, first_name=encrypt_first_name("first"), last_name=None)

        asyncio.run(contractor.decrypt())

        assert contractor.first_name == "first"
        assert contractor.last_name is None

    def test_walks_loaded_relationships(self):
        org = BulkOrg(id=1, name="Acme")
        contractor = BulkContractor(id=1, first_name=encrypt_first_name("first"), last_name=None)
        org.contractors = [contractor]

        asyncio.run(org.decrypt())

        assert contractor.first_name == "first"

    def test_all_columns_none(self):
        contractor = BulkContractor(id=1, first_name=None, last_name=None)

        asyncio.run(contractor.decrypt())

        assert contractor.first_name is None
        assert contractor.last_name is None


class TestDecryptValues:
    """Test the decrypt_values bulk helper for flat ciphertext iterables."""

    CONTEXT = "_bulk_test_contractor.first_name"

    def make_ciphertext(self, value: str) -> bytes:
        """Encrypt a value under the column the flat list is drained from."""

        return encrypt_first_name(value)

    def test_decrypts_list_of_ciphertexts(self):
        values = [self.make_ciphertext(f"user-{i}") for i in range(3)]

        result = asyncio.run(decrypt_values(values, context=self.CONTEXT))

        assert result == ["user-0", "user-1", "user-2"]

    def test_preserves_none_positions(self):
        values = [
            self.make_ciphertext("a"),
            None,
            self.make_ciphertext("b"),
            None,
        ]

        result = asyncio.run(decrypt_values(values, context=self.CONTEXT))

        assert result == ["a", None, "b", None]

    def test_empty_input(self):
        assert asyncio.run(decrypt_values([], context=self.CONTEXT)) == []

    def test_passes_through_non_bytes_cells(self):
        values = [self.make_ciphertext("a"), 42, "plain", None]

        result = asyncio.run(decrypt_values(values, context=self.CONTEXT))

        assert result == ["a", 42, "plain", None]


class TestColumnContext:
    """Test that column_context resolves the associated data a column binds its cells to."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_resolves_an_encrypted_column(self):
        """Test that an encrypted column reports the context its own type carries."""

        row = DeferPair(id=1)

        assert column_context(row, "email") == b"_defer_pair.email"

    def test_resolves_an_encrypted_array_column(self):
        """Test that an encrypted array column reports its element type's context."""

        row = ArrayRow(id=1)

        assert column_context(row, "tags") == b"_array_row.tags"

    def test_rejects_a_column_that_is_not_encrypted(self):
        """Test that a column binding no context raises instead of decrypting unbound."""

        row = BulkOrg(id=1, name="Acme")

        with pytest.raises(ValueError, match="does not encrypt its values"):
            column_context(row, "name")


class TestCrossColumnCiphertext:
    """Test that a value written through one column cannot be read through another."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_ciphertext_moved_between_columns_fails_to_open(self):
        """Test that a cell holding another column's ciphertext raises instead of decrypting."""

        row = DeferPair(secret=encrypt_through_column(DeferPair.__table__.c.email, "a@x.com"))

        with pytest.raises(BaseExceptionGroup) as raised:
            asyncio.run(decrypt_rows([row], "secret"))

        assert raised.group_contains(InvalidToken)
