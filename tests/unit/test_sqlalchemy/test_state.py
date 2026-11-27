import uuid
from collections import defaultdict
from decimal import Decimal
from weakref import WeakSet

import pytest
from sqlalchemy import Column, MetaData, Numeric, Table, Uuid
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Session
from sqlalchemy.types import TypeEngine

from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.integrations.sqlalchemy.state import (
    PENDING_DECRYPT_KEY,
    pending_siblings,
    read_raw_cell,
    row_key_segment,
    sealed_row_key,
    set_decrypted,
    table_row_key,
)
from tests.unit.test_sqlalchemy.tables import (
    CompositeKeyedRow,
    KeyedTier,
    Organization,
    SecretRow,
    ServerKeyedRow,
    UnmappedRow,
)
from tests.unit.test_sqlalchemy.utils import column_type_of


class TestState:
    """Test the helpers that read and write a row's cells, name its row and list its pending siblings."""

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

    def test_table_row_key_composite_segments(self, postgresql_dialect: Dialect):
        """Test that a composite primary key yields one canonical segment per column, in key order."""

        key_id = uuid.uuid4()

        assert table_row_key(
            CompositeKeyedRow.__table__,
            {"id": str(key_id).upper(), "slug": "main", "tenant": "7"},
            postgresql_dialect,
        ) == ["7", "main", str(key_id)]

    def test_table_row_key_matches_orm_context(self, postgresql_dialect: Dialect):
        """Test that the Core key opens the context the ORM seals the same row's cell under."""

        key_id = uuid.uuid4()
        row = CompositeKeyedRow(tenant=7, slug="main", id=key_id, secret="secret data")
        column_type = column_type_of(CompositeKeyedRow.__table__.c.secret, SQLAlchemyEncryptedValue)
        key = table_row_key(
            CompositeKeyedRow.__table__, {"tenant": 7, "slug": "main", "id": key_id}, postgresql_dialect
        )

        assert key == sealed_row_key(sa_inspect(CompositeKeyedRow), row)
        assert column_type.cell_context(*key) == column_type.context_for(row)

    @pytest.mark.parametrize(
        ("key_type", "dialect", "refusal"),
        [
            (Numeric(10, 2), postgresql.dialect(), "is a primary key of type"),
            (Uuid(native_uuid=False), postgresql.dialect(), "is a UUID primary key stored as text"),
            (Uuid(), sqlite.dialect(), "is a UUID primary key stored as text"),
        ],
        ids=["numeric", "uuid-declared-as-text", "uuid-on-text-dialect"],
    )
    def test_table_row_key_unreadable_type_refused(
        self, key_type: TypeEngine[object], dialect: Dialect, refusal: str
    ):
        """Test that a table whose primary key can read back changed is refused, naming the table."""

        table = Table("key_type_rows", MetaData(), Column("id", key_type, primary_key=True), schema="main")

        with pytest.raises(ValueError, match=rf"main\.key_type_rows\.id {refusal}"):
            table_row_key(table, {"id": 1}, dialect)

    @pytest.mark.parametrize(
        "key_values",
        [{"tenant": 7, "slug": "main"}, {"tenant": 7, "slug": "main", "id": None}],
        ids=["absent", "none"],
    )
    def test_table_row_key_absent_value_refused(
        self, postgresql_dialect: Dialect, key_values: dict[str, object]
    ):
        """Test that a key column the row gives no value for is refused as the ORM refuses an unkeyed row."""

        with pytest.raises(ValueError, match="Row of main.composite_keyed_rows has no id yet"):
            table_row_key(CompositeKeyedRow.__table__, key_values, postgresql_dialect)

    @pytest.mark.parametrize(
        ("value", "segment"),
        [(7, "7"), (-7, "-7"), (0, "0"), ("7", "7"), ("-7", "-7"), (KeyedTier.GOLD, "7")],
        ids=["int", "negative-int", "zero", "text", "negative-text", "named-int"],
    )
    def test_integer_key_canonical_form(self, value: int | str, segment: str):
        """Test that an integer key, as a number or its canonical text, names its row by its decimal digits."""

        assert row_key_segment(ServerKeyedRow.__table__.c.id, value) == segment

    @pytest.mark.parametrize(
        "value",
        ["7_0", "07", " 7", "+7", "-0", "7.0", "٧", True, Decimal(7)],
        ids=[
            "underscore",
            "padded",
            "space",
            "plus",
            "negative-zero",
            "fraction",
            "other-digits",
            "bool",
            "decimal",
        ],
    )
    def test_integer_key_refuses_other_spellings(self, value: object):
        """Test that an integer key segment refuses whatever is not an integer or its canonical decimal form."""

        with pytest.raises(ValueError, match="not an integer, nor its canonical decimal form"):
            row_key_segment(ServerKeyedRow.__table__.c.id, value)
