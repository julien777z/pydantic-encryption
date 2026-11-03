import uuid
from collections.abc import Callable
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from pydantic_encryption.types import BlindIndexValue, HashedValue
from tests.factories import User as SampleUser
from tests.integration.database import User


class TestIntegrationSQLAlchemy:
    """Test that encrypted, hashed and blind-index columns round-trip through Postgres."""

    def test_secure_fields(self, create_user: Callable[[User], User], user: SampleUser):
        """Test that an encrypted column reads back as its plaintext and a hashed one as a hash."""

        stored = create_user(User(username=user.username, email=user.first_name, password=user.last_name))

        assert stored.email == user.first_name
        assert isinstance(stored.password, HashedValue)

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            ("email", "sample text"),
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
        self, create_user: Callable[[User], User], user: SampleUser, column: str, value: object
    ):
        """Test that a value written to an encrypted column reads back equal and of the same type."""

        written = User(username=user.username, password=user.last_name)
        setattr(written, column, value)

        stored = getattr(create_user(written), column)

        assert stored == value
        assert type(stored) is type(value)

    @pytest.mark.parametrize("column", ["blind_index_email", "blind_index_email_argon2"])
    def test_blind_index_stored(self, create_user: Callable[[User], User], user: SampleUser, column: str):
        """Test that a blind-index column stores a 32-byte index."""

        written = User(username=user.username, password=user.last_name)
        setattr(written, column, user.first_name)

        stored = getattr(create_user(written), column)

        assert isinstance(stored, BlindIndexValue)
        assert len(stored) == 32

    def test_blind_index_none(self, create_user: Callable[[User], User], user: SampleUser):
        """Test that blind-index columns left unset store nothing."""

        stored = create_user(User(username=user.username, password=user.last_name))

        assert stored.blind_index_email is None
        assert stored.blind_index_email_argon2 is None

    def test_blind_index_query(
        self, create_user: Callable[[User], User], db_session: Session, user: SampleUser
    ):
        """Test that querying a blind-index column by plaintext finds the row it indexes."""

        create_user(User(username=user.username, password=user.last_name, blind_index_email=user.first_name))

        found = db_session.scalars(select(User).where(User.blind_index_email == user.first_name)).first()

        assert found is not None
        assert found.username == user.username

    def test_blind_index_follows_value(
        self, create_user: Callable[[User], User], user: SampleUser, other_user: SampleUser
    ):
        """Test that equal values share one index across rows and different values do not."""

        first = create_user(
            User(username=user.username, password=user.last_name, blind_index_email=user.first_name)
        )
        same = create_user(
            User(username=other_user.username, password=user.last_name, blind_index_email=user.first_name)
        )
        different = create_user(
            User(
                username=other_user.username, password=user.last_name, blind_index_email=other_user.first_name
            )
        )

        assert first.blind_index_email == same.blind_index_email
        assert first.blind_index_email != different.blind_index_email
