import asyncio

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.bulk import (
    collect_encrypted_cells,
    decrypt_rows,
    decrypt_rows_sync,
    decrypt_values,
    resolve_backend,
)
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class GuardBase(DeclarativeBase):
    """Isolated declarative base for the bulk-path guards."""


class GuardOwner(GuardBase, DeferredDecryptMixin):
    """Mapped class owning the rows the bulk paths walk into."""

    __tablename__ = "guard_owners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    name: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    children: Mapped[list["GuardChild"]] = relationship(back_populates="owner")


class GuardChild(GuardBase, DeferredDecryptMixin):
    """Mapped class reached through the owner's relationship."""

    __tablename__ = "guard_children"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("guard_owners.id"), nullable=True)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    owner: Mapped[GuardOwner | None] = relationship(back_populates="children")


class TestResolveBackend:
    """Test the backend lookup every bulk path starts from."""

    def test_an_unset_method_is_refused(self, monkeypatch: pytest.MonkeyPatch):
        """Test that decrypting with no configured method raises rather than guessing one."""

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            resolve_backend()


class TestNamingNoColumns:
    """Test what the row paths do when no column is named."""

    def test_async_decrypt_of_no_columns_does_nothing(self):
        """Test that naming no column leaves the rows untouched instead of reaching for a backend."""

        row = GuardOwner(id=1, secret=encrypt_through_column(GuardOwner.__table__.c.secret, "sealed"))

        asyncio.run(decrypt_rows([row]))

        assert isinstance(row.__dict__["secret"], object)

    def test_sync_decrypt_of_no_columns_does_nothing(self):
        """Test that the sync fallback also leaves the rows untouched when no column is named."""

        row = GuardOwner(id=2, secret=encrypt_through_column(GuardOwner.__table__.c.secret, "sealed"))

        decrypt_rows_sync([row])

        assert isinstance(row.__dict__["secret"], object)

    def test_decrypting_values_with_no_ciphertexts_returns_them_as_they_are(self):
        """Test that a list holding no ciphertext is returned without reaching for a backend."""

        values = [None, "plain", 42]

        assert asyncio.run(decrypt_values(values, context=GuardOwner.secret)) == values


class UndeferredBase(DeclarativeBase):
    """Isolated declarative base for a class that never installs the deferred read path."""


class UndeferredOwner(UndeferredBase):
    """Mapped class with an encrypted column whose type is not marked deferred."""

    __tablename__ = "undeferred_owners"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


class TestCollectEncryptedCells:
    """Test which entities the deferred walk collects encrypted cells from."""

    def test_absent_entities_are_skipped(self):
        """Test that ``None`` in place of an entity is passed over rather than inspected."""

        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells([None], collected, set())

        assert collected == {}

    def test_unmapped_entities_are_skipped(self):
        """Test that an object the ORM does not map carries no cells to collect."""

        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells([object()], collected, set())

        assert collected == {}

    def test_an_unloaded_relationship_is_not_walked(self):
        """Test that a relationship holding nothing is passed over rather than walked into."""

        owner = GuardOwner(
            id=3, secret=encrypt_through_column(GuardOwner.__table__.c.secret, "sealed"), children=[]
        )
        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells(owner, collected, set())

        assert list(collected) == [(GuardOwner, "secret")]

    def test_a_loaded_relationship_is_walked(self):
        """Test that entities reached through a loaded relationship have their cells collected."""

        child = GuardChild(id=4, secret=encrypt_through_column(GuardChild.__table__.c.secret, "sealed"))
        owner = GuardOwner(
            id=5,
            secret=encrypt_through_column(GuardOwner.__table__.c.secret, "sealed"),
            children=[child],
        )
        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells(owner, collected, set())

        assert set(collected) == {(GuardOwner, "secret"), (GuardChild, "secret")}

    def test_a_column_outside_the_deferred_path_is_skipped(self):
        """Test that an encrypted column whose class never deferred reads carries no cell to collect."""

        row = UndeferredOwner(
            id=8, secret=encrypt_through_column(UndeferredOwner.__table__.c.secret, "sealed")
        )
        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells(row, collected, set())

        assert collected == {}

    def test_an_absent_related_entity_is_skipped(self):
        """Test that a relationship loaded as absent is passed over rather than walked into."""

        child = GuardChild(
            id=9, secret=encrypt_through_column(GuardChild.__table__.c.secret, "sealed"), owner=None
        )
        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells(child, collected, set())

        assert list(collected) == [(GuardChild, "secret")]

    def test_a_single_valued_relationship_is_walked(self):
        """Test that a relationship holding one entity is walked like a collection of one."""

        owner = GuardOwner(id=6, secret=encrypt_through_column(GuardOwner.__table__.c.secret, "sealed"))
        child = GuardChild(
            id=7, secret=encrypt_through_column(GuardChild.__table__.c.secret, "sealed"), owner=owner
        )
        collected: dict[tuple[type, str], list[object]] = {}

        collect_encrypted_cells(child, collected, set())

        assert set(collected) == {(GuardOwner, "secret"), (GuardChild, "secret")}
