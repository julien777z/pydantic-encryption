import uuid

from argon2 import PasswordHasher
from sqlalchemy import insert, select, text
from sqlalchemy.orm import Session

from tests.integration.database import Record
from tests.models.records import SampleRecord


class TestBinaryLiteralRoundTrip:
    """Test that column values rendered as literal SQL round-trip through Postgres."""

    def test_literal_round_trip(self, db_session: Session, sample: SampleRecord):
        """Test that every column type written and queried through literal SQL reads back as bound SQL would."""

        dialect = db_session.get_bind().dialect
        tags = [sample.label, None, sample.caption]
        insert_statement = insert(Record).values(
            id=uuid.uuid4(),
            name=sample.name,
            note=sample.label,
            password=sample.caption,
            tags=tags,
            blind_index_note=sample.name,
        )

        db_session.execute(
            text(str(insert_statement.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
        )

        lookup = select(Record.name).where(Record.blind_index_note == sample.name)
        found = db_session.execute(
            text(str(lookup.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
        ).scalar_one()
        stored = db_session.scalars(select(Record).where(Record.name == sample.name)).one()

        assert found == sample.name
        assert stored.note == sample.label
        assert stored.tags == tags
        assert PasswordHasher().verify(stored.password.decode("utf-8"), sample.caption)
