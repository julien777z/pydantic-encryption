import uuid

from argon2 import PasswordHasher
from sqlalchemy import insert, select, text
from sqlalchemy.orm import Session

from tests.factories import User as SampleUser
from tests.integration.database import User


class TestBinaryLiteralRoundTrip:
    """Test that column values rendered as literal SQL round-trip through Postgres."""

    def test_literal_round_trip(self, db_session: Session, user: SampleUser):
        """Test that every column type written and queried through literal SQL reads back as bound SQL would."""

        dialect = db_session.get_bind().dialect
        tags = [user.first_name, None, user.last_name]
        insert_statement = insert(User).values(
            id=uuid.uuid4(),
            username=user.username,
            email=user.first_name,
            password=user.last_name,
            tags=tags,
            blind_index_email=user.username,
        )

        db_session.execute(
            text(str(insert_statement.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
        )

        lookup = select(User.username).where(User.blind_index_email == user.username)
        found = db_session.execute(
            text(str(lookup.compile(dialect=dialect, compile_kwargs={"literal_binds": True})))
        ).scalar_one()
        stored = db_session.scalars(select(User).where(User.username == user.username)).one()

        assert found == user.username
        assert stored.email == user.first_name
        assert stored.tags == tags
        assert PasswordHasher().verify(stored.password.decode("utf-8"), user.last_name)
