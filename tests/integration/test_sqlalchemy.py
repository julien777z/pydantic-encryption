from datetime import date, datetime, timezone
from typing import Final

from sqlalchemy.orm import Session

from tests.integration.database import User

TEST_PASSWORD: Final[str] = "pass123"
TEST_EMAIL: Final[str] = "user1@example.com"
TEST_BIRTH_DATE: Final[date] = date(1990, 5, 15)
TEST_LAST_LOGIN: Final[datetime] = datetime(2025, 1, 21, 14, 30, 45)
TEST_AGE: Final[int] = 34
TEST_SECRET_DATA: Final[bytes] = b"\x00\x01\x02\x03binary\xff\xfe"


class TestIntegrationSQLAlchemy:
    """Test the integration with SQLAlchemy."""

    def _create_user(
        self,
        db_session: Session,
        username: str,
        password: str,
        birth_date: date | None = None,
        last_login: datetime | None = None,
        age: int | None = None,
        secret_data: bytes | None = None,
    ) -> User:
        """Create a user."""

        user = User(
            username=username,
            email=TEST_EMAIL,
            password=password,
            birth_date=birth_date,
            last_login=last_login,
            age=age,
            secret_data=secret_data,
        )
        db_session.add(user)
        db_session.commit()

        return db_session.query(User).filter_by(username=username).first()

    def test_secure_fields(self, db_session: Session):
        """Test encrypting and hashing fields with the SQLAlchemyEncrypted and SQLAlchemyHashed types."""

        user = self._create_user(db_session, username="user1", password=TEST_PASSWORD)

        assert user.username == "user1"
        assert user.email == TEST_EMAIL
        assert getattr(user.password, "hashed") is True

    def test_encrypt_decrypt_date(self, db_session: Session):
        """Test that date fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user2", password=TEST_PASSWORD, birth_date=TEST_BIRTH_DATE
        )

        assert user.birth_date == TEST_BIRTH_DATE
        assert isinstance(user.birth_date, date)

    def test_encrypt_decrypt_datetime(self, db_session: Session):
        """Test that datetime fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user3", password=TEST_PASSWORD, last_login=TEST_LAST_LOGIN
        )

        assert user.last_login == TEST_LAST_LOGIN
        assert isinstance(user.last_login, datetime)

    def test_encrypt_decrypt_datetime_with_timezone(self, db_session: Session):
        """Test that timezone-aware datetime fields preserve timezone."""

        test_datetime = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)

        user = self._create_user(
            db_session, username="user4", password=TEST_PASSWORD, last_login=test_datetime
        )

        assert user.last_login == test_datetime
        assert user.last_login.tzinfo is not None

    def test_null_date_handling(self, db_session: Session):
        """Test that None values are handled correctly."""

        user = self._create_user(
            db_session, username="user5", password=TEST_PASSWORD, birth_date=None, last_login=None
        )

        assert user.birth_date is None
        assert user.last_login is None

    def test_encrypt_decrypt_int(self, db_session: Session):
        """Test that integer fields are encrypted and decrypted correctly."""

        user = self._create_user(db_session, username="user6", password=TEST_PASSWORD, age=TEST_AGE)

        assert user.age == TEST_AGE
        assert isinstance(user.age, int)

    def test_encrypt_decrypt_bytes(self, db_session: Session):
        """Test that bytes fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user7", password=TEST_PASSWORD, secret_data=TEST_SECRET_DATA
        )

        assert user.secret_data == TEST_SECRET_DATA
        assert isinstance(user.secret_data, bytes)

    def test_encrypt_decrypt_str(self, db_session: Session):
        """Test that string fields are encrypted and decrypted correctly."""

        user = self._create_user(db_session, username="user8", password=TEST_PASSWORD)

        assert user.email == TEST_EMAIL
        assert isinstance(user.email, str)
