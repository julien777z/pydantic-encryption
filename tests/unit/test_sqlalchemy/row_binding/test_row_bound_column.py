import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy import inspect as sa_inspect, select
from sqlalchemy.exc import StatementError
from sqlalchemy.orm import Session

from pydantic_encryption.context import derive_row_context
from pydantic_encryption.integrations.sqlalchemy.state import read_raw_cell
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.tables import ColumnBoundRow, RowBoundRecord, ServerKeyedRow, UndeferredRow
from tests.unit.test_sqlalchemy.utils import column_type_of
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue


class TestRowBoundColumn:
    """Test that a row-bound column binds each cell to the row it belongs to."""

    def test_round_trip_through_own_row(self, sqlite_session: Session):
        """Test that a row-bound cell decrypts when read back from its own row."""

        sqlite_session.add(RowBoundRecord(secret="secret-one"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        stored = sqlite_session.execute(select(RowBoundRecord)).scalar_one()

        assert stored.secret == "secret-one"

    def test_cell_binds_to_the_context_naming_its_row(self, sqlite_session: Session):
        """Test that a cell is sealed under the context naming its table, column and row."""

        member = RowBoundRecord(secret="secret-one")
        sqlite_session.add(member)
        sqlite_session.commit()
        sqlite_session.refresh(member)

        column_type = column_type_of(RowBoundRecord.__table__.c.secret, SQLAlchemyEncryptedValue)
        expected = derive_row_context("row_bound_records", "secret", str(member.id))

        cell = read_raw_cell(member, "secret")

        assert column_type.cell_context(str(member.id)) == expected
        assert isinstance(cell, EncryptedValue)
        assert column_type.decrypt_cell(cell, context=expected)

    def test_ciphertext_moved_to_another_row_fails_to_open(self, sqlite_session: Session):
        """Test that a cell carrying another row's ciphertext raises instead of decrypting."""

        first = RowBoundRecord(secret="secret-one")
        second = RowBoundRecord(secret="secret-two")
        sqlite_session.add_all([first, second])
        sqlite_session.commit()

        first_id, second_id = first.id, second.id
        sqlite_session.expunge_all()

        rows = {row.id: row for row in sqlite_session.execute(select(RowBoundRecord)).scalars()}
        stolen = read_raw_cell(rows[second_id], "secret")

        assert isinstance(stolen, EncryptedValue)

        victim = rows[first_id]
        sa_inspect(victim).dict["secret"] = stolen

        with pytest.raises(InvalidToken):
            victim.secret

    def test_update_reseals_under_the_same_row(self, sqlite_session: Session):
        """Test that updating a row-bound cell keeps it readable from its own row."""

        member = RowBoundRecord(secret="secret-one")
        sqlite_session.add(member)
        sqlite_session.commit()

        member.secret = "secret-three"
        sqlite_session.commit()
        sqlite_session.expunge_all()

        assert sqlite_session.execute(select(RowBoundRecord)).scalar_one().secret == "secret-three"

    def test_empty_cell_stays_empty(self, sqlite_session: Session):
        """Test that a row-bound column leaves a cell holding nothing alone."""

        sqlite_session.add(RowBoundRecord())
        sqlite_session.commit()
        sqlite_session.expunge_all()

        assert sqlite_session.execute(select(RowBoundRecord)).scalar_one().secret is None

    def test_column_bound_row_untouched(self, sqlite_session: Session):
        """Test that a class with no row-bound column writes and reads as it otherwise would."""

        sqlite_session.add(ColumnBoundRow(secret="secret data"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        assert sqlite_session.execute(select(ColumnBoundRow)).scalar_one().secret == "secret data"

    def test_server_generated_key_is_refused(self, sqlite_session: Session):
        """Test that a key which does not exist before its insert cannot bind a row."""

        sqlite_session.add(ServerKeyedRow(secret="secret data"))

        with pytest.raises(ValueError, match="has no id yet"):
            sqlite_session.flush()

    def test_undeferred_row_bound_column_refused(self, sqlite_session: Session):
        """Test that a row-bound column raises where nothing carries the row to its cells."""

        sqlite_session.add(UndeferredRow(secret="secret data"))

        with pytest.raises(StatementError, match="binds each row separately"):
            sqlite_session.flush()
