import uuid
from collections import defaultdict
from weakref import WeakSet

import pytest
from sqlalchemy import CHAR, Column, DateTime, MetaData, Numeric, Table
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeEngine

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    pending_siblings,
    read_raw_cell,
    sealed_row_key,
    set_decrypted,
    table_row_key,
)
from tests.unit.test_sqlalchemy.tables import CompositeKeyedRow, Organization, SecretRow, UnmappedRow
from tests.unit.test_sqlalchemy.utils import column_type_of


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


class TestTableRowKey:
    """Test the row key a Core table row's cells are sealed under, against the ORM's for the same row."""

    KEY_ID = uuid.UUID("0b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8")

    def test_composite_key_gives_one_segment_per_column(self):
        """Test that a composite primary key yields one canonical segment per column, in key order."""

        table = CompositeKeyedRow.__table__

        assert table_row_key(table, {"id": str(self.KEY_ID).upper(), "slug": "main", "tenant": "7"}) == [
            "7",
            "main",
            str(self.KEY_ID),
        ]

    def test_matches_orm_cell_context(self):
        """Test that the Core key opens the context the ORM seals the same row's cell under."""

        row = CompositeKeyedRow(tenant=7, slug="main", id=self.KEY_ID, secret="secret data")
        column_type = column_type_of(CompositeKeyedRow.__table__.c.secret, SQLAlchemyEncryptedValue)
        key = table_row_key(CompositeKeyedRow.__table__, {"tenant": 7, "slug": "main", "id": self.KEY_ID})

        assert key == sealed_row_key(sa_inspect(CompositeKeyedRow), row)
        assert column_type.cell_context(*key) == column_type.context_for(row)

    @pytest.mark.parametrize(
        "key_type", [Numeric(10, 2), DateTime(timezone=True), CHAR(8)], ids=["numeric", "datetime", "char"]
    )
    def test_unreadable_key_type_refused(self, key_type: TypeEngine[object]):
        """Test that a table whose primary key can read back changed is refused, naming the table."""

        table = Table("key_type_rows", MetaData(), Column("id", key_type, primary_key=True), schema="main")

        with pytest.raises(ValueError, match=r"main\.key_type_rows\.id is a primary key of type"):
            table_row_key(table, {"id": 1})

    @pytest.mark.parametrize(
        "key_values",
        [{"tenant": 7, "slug": "main"}, {"tenant": 7, "slug": "main", "id": None}],
        ids=["absent", "none"],
    )
    def test_absent_key_value_refused(self, key_values: dict[str, object]):
        """Test that a key column the row gives no value for is refused as the ORM refuses an unkeyed row."""

        with pytest.raises(ValueError, match="Row of main.composite_keyed_rows has no id yet"):
            table_row_key(CompositeKeyedRow.__table__, key_values)
