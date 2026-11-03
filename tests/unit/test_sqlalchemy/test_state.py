from collections import defaultdict
from weakref import WeakSet

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    pending_siblings,
    read_raw_cell,
    set_decrypted,
)
from tests.unit.test_sqlalchemy.tables import Organization, SecretRow, UnmappedRow


class TestState:
    """Test the helpers that read and write a row's stored cells and its session's pending rows."""

    def test_mapped_row_read_from_state(self):
        """Test that a mapped row's cell is read from its ORM state."""

        assert read_raw_cell(Organization(id=1, name="sample organization"), "name") == "sample organization"

    def test_unmapped_row_read_by_attribute(self):
        """Test that an object with no ORM state is read by attribute, and a missing one reads as None."""

        assert read_raw_cell(UnmappedRow("secret data"), "secret") == "secret data"
        assert read_raw_cell(UnmappedRow(), "missing") is None

    def test_mapped_row_takes_value_without_dirtying(self):
        """Test that a mapped row takes a decrypted value without becoming dirty for the next flush."""

        organization = Organization(id=1, name="sealed")
        state = sa_inspect(organization)
        state._commit_all(state.dict)

        set_decrypted(organization, "name", "sample organization")

        assert organization.name == "sample organization"
        assert not state.attrs.name.history.has_changes()

    def test_unmapped_row_takes_value_by_assignment(self):
        """Test that an object with no ORM state takes a decrypted value by plain assignment."""

        row = UnmappedRow("sealed")

        set_decrypted(row, "secret", "secret data")

        assert row.secret == "secret data"

    def test_session_without_bucket_has_no_siblings(self):
        """Test that a session with no pending-decrypt bucket has no siblings."""

        assert pending_siblings(Session(), SecretRow) == []

    def test_bucketed_rows_returned_as_siblings(self):
        """Test that the rows bucketed for a class are its siblings while the session holds them."""

        rows = [SecretRow(id=1), SecretRow(id=2), SecretRow(id=3)]
        bucket: defaultdict[type[object], WeakSet[object]] = defaultdict(WeakSet)
        bucket[SecretRow].update(rows)
        session = Session()
        session.add_all(rows)
        session.info[PENDING_DECRYPT_KEY] = bucket

        session.expunge(rows[2])

        assert set(pending_siblings(session, SecretRow)) == set(rows[:2])
