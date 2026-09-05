import uuid
from collections.abc import Iterator

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import Integer, MetaData, String, Uuid, create_engine, func, select
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


class RowBoundRecord(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose encrypted column binds each row separately."""

    __tablename__ = "row_bound_records"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    label: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    secret: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(row_bound=True), nullable=True, default=None
    )


class ExpressionKeyedRow(RowBoundBase, DeferredDecryptMixin):
    """Mapped class whose primary key defaults to an expression the database evaluates."""

    __tablename__ = "expression_keyed_rows"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=func.gen_random_uuid())
    secret: Mapped[bytes | None] = mapped_column(
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

        session.add(RowBoundRecord(secret="secret-one"))
        session.commit()
        session.expunge_all()

        stored = session.execute(select(RowBoundRecord)).scalar_one()

        assert stored.secret == "secret-one"

    def test_cell_binds_to_the_context_naming_its_row(self, session: Session):
        """Test that a cell is sealed under the context naming its table, column and row."""

        member = RowBoundRecord(secret="secret-one")
        session.add(member)
        session.commit()
        session.refresh(member)

        column_type = RowBoundRecord.__table__.c.secret.type
        expected = derive_row_context("row_bound_records", "secret", str(member.id))

        assert column_type.cell_context(str(member.id)) == expected
        assert column_type.decrypt_cell(bytes(read_raw_cell(member, "secret")), context=expected)

    def test_ciphertext_moved_to_another_row_fails_to_open(self, session: Session):
        """Test that a cell carrying another row's ciphertext raises instead of decrypting."""

        first = RowBoundRecord(secret="secret-one")
        second = RowBoundRecord(secret="secret-two")
        session.add_all([first, second])
        session.commit()

        first_id, second_id = first.id, second.id
        session.expunge_all()

        rows = {row.id: row for row in session.execute(select(RowBoundRecord)).scalars()}
        stolen = EncryptedValue(bytes(read_raw_cell(rows[second_id], "secret")))
        victim = rows[first_id]
        victim.__dict__["secret"] = stolen

        with pytest.raises(InvalidToken):
            victim.secret

    def test_update_reseals_under_the_same_row(self, session: Session):
        """Test that updating a row-bound cell keeps it readable from its own row."""

        member = RowBoundRecord(secret="secret-one")
        session.add(member)
        session.commit()

        member.secret = "secret-three"
        session.commit()
        session.expunge_all()

        assert session.execute(select(RowBoundRecord)).scalar_one().secret == "secret-three"

    def test_empty_cell_stays_empty(self, session: Session):
        """Test that a row-bound column leaves a cell holding nothing alone."""

        session.add(RowBoundRecord())
        session.commit()
        session.expunge_all()

        assert session.execute(select(RowBoundRecord)).scalar_one().secret is None

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

        column_bound = SQLAlchemyEncryptedValue("users.secret")
        row_bound = SQLAlchemyEncryptedValue("users.secret", row_bound=True)

        assert column_bound._static_cache_key != row_bound._static_cache_key

    def test_bound_context_refuses_a_row_bound_column(self):
        """Test that asking a row-bound column for one context raises rather than binding the column."""

        with pytest.raises(ValueError, match="binds each row separately"):
            SQLAlchemyEncryptedValue("users.secret", row_bound=True).bound_context()


class TestRowBoundPrimaryKeyDefaults:
    """Test which primary-key defaults can name a row before the insert that stores it."""

    def test_a_key_defaulting_to_an_expression_is_refused(self, session: Session):
        """Test that a key the database computes raises rather than naming the row by its expression."""

        session.add(ExpressionKeyedRow(secret="secret data"))

        with pytest.raises(ValueError, match="defaults to a SQL expression"):
            session.flush()


class TestRowKeyChanges:
    """Test what happens to a row-bound cell when the row it names is renamed."""

    def test_a_cell_follows_its_row_to_a_new_primary_key(self, session: Session):
        """Test that changing a primary key re-seals the cells bound to the row it named."""

        record = RowBoundRecord(secret="secret-one")
        session.add(record)
        session.flush()
        session.expunge_all()

        moved = session.execute(select(RowBoundRecord)).scalar_one()
        moved.id = uuid.uuid4()
        session.flush()
        moved_id = moved.id
        session.expunge_all()

        reloaded = session.get(RowBoundRecord, moved_id)

        assert reloaded is not None
        assert reloaded.secret == "secret-one"

    def test_a_cell_is_left_alone_when_the_row_keeps_its_key(self, session: Session):
        """Test that updating another column leaves a sealed cell exactly as it was."""

        record = RowBoundRecord(secret="secret-one", label="before")
        session.add(record)
        session.flush()
        record_id = record.id
        session.expunge_all()

        stored = session.get(RowBoundRecord, record_id)
        assert stored is not None
        stored.label = "after"
        session.flush()
        session.expunge_all()

        reloaded = session.get(RowBoundRecord, record_id)

        assert reloaded is not None
        assert reloaded.label == "after"
        assert reloaded.secret == "secret-one"


class TestSharedColumnTypes:
    """Test what one encrypted type does when more than one column reaches for it."""

    def test_one_type_refuses_a_second_column(self):
        """Test that a type already bound to a column refuses to rebind what that column wrote."""

        shared = SQLAlchemyEncryptedValue()

        class SharedBase(DeclarativeBase):
            """Isolated declarative base for the shared-type test."""

        class FirstOwner(SharedBase):
            """Mapped class claiming the shared type first."""

            __tablename__ = "first_owners"

            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            secret: Mapped[bytes | None] = mapped_column(shared, nullable=True, default=None)

        with pytest.raises(ValueError, match="already bound to"):

            class SecondOwner(SharedBase):
                """Mapped class reaching for a type another column already owns."""

                __tablename__ = "second_owners"

                id: Mapped[int] = mapped_column(Integer, primary_key=True)
                secret: Mapped[bytes | None] = mapped_column(shared, nullable=True, default=None)

    def test_a_copied_type_derives_its_own_context(self):
        """Test that copying a table re-derives the copy's context and its statement cache key."""

        class CopiedBase(DeclarativeBase):
            """Isolated declarative base for the copied-table test."""

        class Original(CopiedBase):
            """Mapped class whose table is copied to another name."""

            __tablename__ = "originals"

            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            secret: Mapped[bytes | None] = mapped_column(
                SQLAlchemyEncryptedValue(), nullable=True, default=None
            )

        source = Original.__table__.c.secret.type
        source_cache_key = source._static_cache_key
        copied = Original.__table__.to_metadata(MetaData(), name="copies").c.secret.type

        assert copied.context == b"copies.secret"
        assert copied._static_cache_key != source_cache_key
