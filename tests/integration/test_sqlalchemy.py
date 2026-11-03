import uuid
from collections.abc import Callable
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from pydantic_encryption.types import BlindIndexValue, HashedValue
from tests.integration.database import Record
from tests.models.records import SampleRecord


class TestIntegrationSQLAlchemy:
    """Test that encrypted, hashed and blind-index columns round-trip through Postgres."""

    def test_secure_fields(self, store_record: Callable[[Record], Record], sample: SampleRecord):
        """Test that an encrypted column reads back as its plaintext and a hashed one as a hash."""

        stored = store_record(Record(name=sample.name, note=sample.label, password=sample.caption))

        assert stored.note == sample.label
        assert isinstance(stored.password, HashedValue)

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            ("note", "sample text"),
            ("birth_date", date(1990, 5, 15)),
            ("birth_date", None),
            ("last_login", datetime(2025, 1, 21, 14, 30, 45)),
            ("last_login", datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)),
            ("age", 34),
            ("secret_data", b"\x00\x01\x02\x03binary\xff\xfe"),
            ("is_active", True),
            ("is_active", False),
            ("is_active", None),
            ("balance", 1234.56),
            ("balance", -123.45),
            ("quantity", Decimal("99999.99")),
            ("quantity", Decimal("123.456789012345678901234567890")),
            ("external_id", uuid.UUID("12345678-1234-5678-1234-567812345678")),
            ("login_time", time(14, 30, 45)),
            ("login_time", time(14, 30, 45, tzinfo=timezone.utc)),
            ("session_duration", timedelta(hours=2, minutes=30)),
            ("session_duration", timedelta(days=-1, hours=-5)),
            ("tags", ["tag1", "tag2", "tag3"]),
            ("tags", ["only"]),
            ("tags", []),
            ("tags", None),
        ],
        ids=[
            "str",
            "date",
            "date-none",
            "datetime",
            "datetime-with-timezone",
            "int",
            "bytes",
            "bool-true",
            "bool-false",
            "bool-none",
            "float",
            "float-negative",
            "decimal",
            "decimal-high-precision",
            "uuid",
            "time",
            "time-with-timezone",
            "timedelta",
            "timedelta-negative",
            "array",
            "array-single",
            "array-empty",
            "array-none",
        ],
    )
    def test_value_round_trip(
        self, store_record: Callable[[Record], Record], sample: SampleRecord, column: str, value: object
    ):
        """Test that a value written to an encrypted column reads back equal and of the same type."""

        written = Record(name=sample.name, password=sample.caption)
        setattr(written, column, value)

        stored = getattr(store_record(written), column)

        assert stored == value
        assert type(stored) is type(value)

    @pytest.mark.parametrize("column", ["blind_index_note", "blind_index_note_argon2"])
    def test_blind_index_stored(
        self, store_record: Callable[[Record], Record], sample: SampleRecord, column: str
    ):
        """Test that a blind-index column stores a 32-byte index."""

        written = Record(name=sample.name, password=sample.caption)
        setattr(written, column, sample.label)

        stored = getattr(store_record(written), column)

        assert isinstance(stored, BlindIndexValue)
        assert len(stored) == 32

    def test_blind_index_none(self, store_record: Callable[[Record], Record], sample: SampleRecord):
        """Test that blind-index columns left unset store nothing."""

        stored = store_record(Record(name=sample.name, password=sample.caption))

        assert stored.blind_index_note is None
        assert stored.blind_index_note_argon2 is None

    def test_blind_index_query(
        self, store_record: Callable[[Record], Record], db_session: Session, sample: SampleRecord
    ):
        """Test that querying a blind-index column by plaintext finds the row it indexes."""

        store_record(Record(name=sample.name, password=sample.caption, blind_index_note=sample.label))

        found = db_session.scalars(select(Record).where(Record.blind_index_note == sample.label)).first()

        assert found is not None
        assert found.name == sample.name

    def test_blind_index_follows_value(
        self, store_record: Callable[[Record], Record], sample: SampleRecord, other_sample: SampleRecord
    ):
        """Test that equal values share one index across rows and different values do not."""

        first = store_record(Record(name=sample.name, password=sample.caption, blind_index_note=sample.label))
        same = store_record(
            Record(name=other_sample.name, password=sample.caption, blind_index_note=sample.label)
        )
        different = store_record(
            Record(name=other_sample.name, password=sample.caption, blind_index_note=other_sample.label)
        )

        assert first.blind_index_note == same.blind_index_note
        assert first.blind_index_note != different.blind_index_note
