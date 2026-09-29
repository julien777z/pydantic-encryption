import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.unit.test_sqlalchemy.tables import RowBoundRecord


class TestRowKeyChanges:
    """Test what happens to a row-bound cell when the row it names is renamed."""

    def test_cell_follows_new_primary_key(self, sqlite_session: Session):
        """Test that changing a primary key re-seals the cells bound to the row it named."""

        record = RowBoundRecord(secret="secret-one")
        sqlite_session.add(record)
        sqlite_session.flush()
        sqlite_session.expunge_all()

        moved = sqlite_session.execute(select(RowBoundRecord)).scalar_one()
        moved.id = uuid.uuid4()
        sqlite_session.flush()
        moved_id = moved.id
        sqlite_session.expunge_all()

        reloaded = sqlite_session.get(RowBoundRecord, moved_id)

        assert reloaded is not None
        assert reloaded.secret == "secret-one"

    def test_cell_untouched_when_key_kept(self, sqlite_session: Session):
        """Test that updating another column leaves a sealed cell exactly as it was."""

        record = RowBoundRecord(secret="secret-one", label="before")
        sqlite_session.add(record)
        sqlite_session.flush()
        record_id = record.id
        sqlite_session.expunge_all()

        stored = sqlite_session.get(RowBoundRecord, record_id)
        assert stored is not None
        stored.label = "after"
        sqlite_session.flush()
        sqlite_session.expunge_all()

        reloaded = sqlite_session.get(RowBoundRecord, record_id)

        assert reloaded is not None
        assert reloaded.label == "after"
        assert reloaded.secret == "secret-one"
