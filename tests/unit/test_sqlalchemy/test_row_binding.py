import uuid
from collections.abc import Iterator

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import Integer, Uuid, create_engine, select
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from pydantic_encryption.context import derive_row_context
from pydantic_encryption.integrations.sqlalchemy import DeferredDecryptMixin
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.integrations.sqlalchemy.state import read_raw_cell
from pydantic_encryption.types import EncryptedValue


class RowBoundBase(DeclarativeBase):
    """Isolated declarative base for the row-binding tests."""


class BoundContractor(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose encrypted column binds each row separately."""

    __tablename__ = "bound_contractors"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tax_id: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ServerKeyedRow(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose primary key does not exist until its insert returns."""

    __tablename__ = "server_keyed_rows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    secret: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class UndeferredRow(RowBoundBase):
    """Mapped class that binds each row but never mixes in the deferred read path."""

    __tablename__ = "undeferred_rows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    secret: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ColumnBoundRow(RowBoundBase, DeferredDecryptMixin):
    """Mapped class on the deferred read path whose encrypted column binds its column only."""

    __tablename__ = "column_bound_rows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    secret: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)


@pytest.fixture
def session() -> Iterator[Session]:
    """Open a session against a fresh in-memory database holding the row-binding tables."""

    engine = create_engine("sqlite://")
    RowBoundBase.metadata.create_all(engine)

    with Session(engine) as open_session:
        yield open_session


class TestRowBoundColumn:
    """Test that a row-bound column binds each cell to the row it belongs to."""

    def test_round_trip_through_the_row_it_was_written_to(self, session: Session):
        """Test that a row-bound cell decrypts when read back from its own row."""

        session.add(BoundContractor(tax_id="111-11-1111"))
        session.commit()
        session.expunge_all()

        stored = session.execute(select(BoundContractor)).scalar_one()

        assert stored.tax_id == "111-11-1111"

    def test_cell_binds_to_the_context_naming_its_row(self, session: Session):
        """Test that a cell is sealed under the context naming its table, column and row."""

        contractor = BoundContractor(tax_id="111-11-1111")
        session.add(contractor)
        session.commit()
        session.refresh(contractor)

        column_type = BoundContractor.__table__.c.tax_id.type
        expected = derive_row_context("bound_contractors", "tax_id", str(contractor.id))

        assert column_type.cell_context(str(contractor.id)) == expected
        assert column_type.decrypt_cell(bytes(read_raw_cell(contractor, "tax_id")), context=expected)

    def test_ciphertext_moved_to_another_row_fails_to_open(self, session: Session):
        """Test that a cell carrying another row's ciphertext raises instead of decrypting."""

        first = BoundContractor(tax_id="111-11-1111")
        second = BoundContractor(tax_id="222-22-2222")
        session.add_all([first, second])
        session.commit()

        first_id, second_id = first.id, second.id
        session.expunge_all()

        rows = {row.id: row for row in session.execute(select(BoundContractor)).scalars()}
        stolen = EncryptedValue(bytes(read_raw_cell(rows[second_id], "tax_id")))
        victim = rows[first_id]
        victim.__dict__["tax_id"] = stolen

        with pytest.raises(InvalidToken):
            victim.tax_id

    def test_update_reseals_under_the_same_row(self, session: Session):
        """Test that updating a row-bound cell keeps it readable from its own row."""

        contractor = BoundContractor(tax_id="111-11-1111")
        session.add(contractor)
        session.commit()

        contractor.tax_id = "333-33-3333"
        session.commit()
        session.expunge_all()

        assert session.execute(select(BoundContractor)).scalar_one().tax_id == "333-33-3333"

    def test_empty_cell_stays_empty(self, session: Session):
        """Test that a row-bound column leaves a cell holding nothing alone."""

        session.add(BoundContractor())
        session.commit()
        session.expunge_all()

        assert session.execute(select(BoundContractor)).scalar_one().tax_id is None

    def test_column_bound_row_is_untouched_by_the_row_bound_write_path(self, session: Session):
        """Test that a class with no row-bound column writes and reads as it otherwise would."""

        session.add(ColumnBoundRow(secret="secret data"))
        session.commit()
        session.expunge_all()

        assert session.execute(select(ColumnBoundRow)).scalar_one().secret == "secret data"

    def test_server_generated_key_is_refused(self, session: Session):
        """Test that a key which does not exist before its insert cannot bind a row."""

        session.add(ServerKeyedRow(secret="secret data"))

        with pytest.raises(ValueError, match="has no id yet"):
            session.flush()

    def test_row_bound_column_without_the_deferred_read_path_is_refused(self, session: Session):
        """Test that a row-bound column raises where nothing carries the row to its cells."""

        session.add(UndeferredRow(secret="secret data"))

        with pytest.raises(StatementError, match="binds each row separately"):
            session.flush()


class TestRowBoundDeclaration:
    """Test what a column type accepts when asked to bind each row."""

    def test_array_refuses_to_bind_a_row(self):
        """Test that an encrypted array refuses row binding rather than promising it."""

        with pytest.raises(ValueError, match="cannot bind its elements to a row"):
            SQLAlchemyPGEncryptedArray(row_bound=True)

    def test_row_binding_changes_the_statement_cache_key(self):
        """Test that a row-bound column cannot share a cache key with a column-bound one."""

        column_bound = SQLAlchemyEncryptedValue("users.tax_id")
        row_bound = SQLAlchemyEncryptedValue("users.tax_id", row_bound=True)

        assert column_bound._static_cache_key != row_bound._static_cache_key

    def test_bound_context_refuses_a_row_bound_column(self):
        """Test that asking a row-bound column for one context raises rather than binding the column."""

        with pytest.raises(ValueError, match="binds each row separately"):
            SQLAlchemyEncryptedValue("users.tax_id", row_bound=True).bound_context()
