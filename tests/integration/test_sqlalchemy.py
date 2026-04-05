import uuid
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from typing import Final

from sqlalchemy.orm import Session

from pydantic_encryption.types import BlindIndexValue

from tests.integration.database import User

TEST_PASSWORD: Final[str] = "pass123"
TEST_EMAIL: Final[str] = "user1@example.com"
TEST_BIRTH_DATE: Final[date] = date(1990, 5, 15)
TEST_LAST_LOGIN: Final[datetime] = datetime(2025, 1, 21, 14, 30, 45)
TEST_AGE: Final[int] = 34
TEST_SECRET_DATA: Final[bytes] = b"\x00\x01\x02\x03binary\xff\xfe"
TEST_BALANCE: Final[float] = 1234.56
TEST_SALARY: Final[Decimal] = Decimal("99999.99")
TEST_EXTERNAL_ID: Final[uuid.UUID] = uuid.UUID("12345678-1234-5678-1234-567812345678")
TEST_LOGIN_TIME: Final[time] = time(14, 30, 45)
TEST_SESSION_DURATION: Final[timedelta] = timedelta(hours=2, minutes=30)


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
        is_active: bool | None = None,
        balance: float | None = None,
        salary: Decimal | None = None,
        external_id: uuid.UUID | None = None,
        login_time: time | None = None,
        session_duration: timedelta | None = None,
        tags: list[str] | None = None,
        blind_index_email: str | None = None,
        blind_index_email_argon2: str | None = None,
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
            is_active=is_active,
            balance=balance,
            salary=salary,
            external_id=external_id,
            login_time=login_time,
            session_duration=session_duration,
            tags=tags,
            blind_index_email=blind_index_email,
            blind_index_email_argon2=blind_index_email_argon2,
        )
        db_session.add(user)
        db_session.commit()

        return db_session.query(User).filter_by(username=username).first()

    def test_secure_fields(self, db_session: Session):
        """Test encrypting and hashing fields with the SQLAlchemyEncryptedValue and SQLAlchemyHashed types."""

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

    def test_encrypt_decrypt_bool_true(self, db_session: Session):
        """Test that boolean True is encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user9", password=TEST_PASSWORD, is_active=True
        )

        assert user.is_active is True
        assert isinstance(user.is_active, bool)

    def test_encrypt_decrypt_bool_false(self, db_session: Session):
        """Test that boolean False is encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user10", password=TEST_PASSWORD, is_active=False
        )

        assert user.is_active is False
        assert isinstance(user.is_active, bool)

    def test_encrypt_decrypt_bool_none(self, db_session: Session):
        """Test that boolean None is handled correctly."""

        user = self._create_user(
            db_session, username="user11", password=TEST_PASSWORD, is_active=None
        )

        assert user.is_active is None

    def test_encrypt_decrypt_float(self, db_session: Session):
        """Test that float fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user12", password=TEST_PASSWORD, balance=TEST_BALANCE
        )

        assert user.balance == TEST_BALANCE
        assert isinstance(user.balance, float)

    def test_encrypt_decrypt_float_negative(self, db_session: Session):
        """Test that negative float values are handled correctly."""

        user = self._create_user(
            db_session, username="user13", password=TEST_PASSWORD, balance=-123.45
        )

        assert user.balance == -123.45

    def test_encrypt_decrypt_decimal(self, db_session: Session):
        """Test that Decimal fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user14", password=TEST_PASSWORD, salary=TEST_SALARY
        )

        assert user.salary == TEST_SALARY
        assert isinstance(user.salary, Decimal)

    def test_encrypt_decrypt_decimal_high_precision(self, db_session: Session):
        """Test that high-precision Decimal values are preserved."""

        high_precision = Decimal("123.456789012345678901234567890")

        user = self._create_user(
            db_session, username="user15", password=TEST_PASSWORD, salary=high_precision
        )

        assert user.salary == high_precision

    def test_encrypt_decrypt_uuid(self, db_session: Session):
        """Test that UUID fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user16", password=TEST_PASSWORD, external_id=TEST_EXTERNAL_ID
        )

        assert user.external_id == TEST_EXTERNAL_ID
        assert isinstance(user.external_id, uuid.UUID)

    def test_encrypt_decrypt_time(self, db_session: Session):
        """Test that time fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user17", password=TEST_PASSWORD, login_time=TEST_LOGIN_TIME
        )

        assert user.login_time == TEST_LOGIN_TIME
        assert isinstance(user.login_time, time)

    def test_encrypt_decrypt_time_with_timezone(self, db_session: Session):
        """Test that timezone-aware time fields preserve timezone."""

        tz_time = time(14, 30, 45, tzinfo=timezone.utc)

        user = self._create_user(
            db_session, username="user18", password=TEST_PASSWORD, login_time=tz_time
        )

        assert user.login_time == tz_time
        assert user.login_time.tzinfo is not None

    def test_encrypt_decrypt_timedelta(self, db_session: Session):
        """Test that timedelta fields are encrypted and decrypted correctly."""

        user = self._create_user(
            db_session, username="user19", password=TEST_PASSWORD, session_duration=TEST_SESSION_DURATION
        )

        assert user.session_duration == TEST_SESSION_DURATION
        assert isinstance(user.session_duration, timedelta)

    def test_encrypt_decrypt_timedelta_negative(self, db_session: Session):
        """Test that negative timedelta values are handled correctly."""

        negative_duration = timedelta(days=-1, hours=-5)

        user = self._create_user(
            db_session, username="user20", password=TEST_PASSWORD, session_duration=negative_duration
        )

        assert user.session_duration == negative_duration

    def test_encrypt_decrypt_array(self, db_session: Session):
        """Test that array fields are encrypted and decrypted correctly."""

        test_tags = ["tag1", "tag2", "tag3"]

        user = self._create_user(
            db_session, username="user21", password=TEST_PASSWORD, tags=test_tags
        )

        assert user.tags == test_tags
        assert isinstance(user.tags, list)

    def test_encrypt_decrypt_array_none(self, db_session: Session):
        """Test that None array values are handled correctly."""

        user = self._create_user(
            db_session, username="user22", password=TEST_PASSWORD, tags=None
        )

        assert user.tags is None

    def test_encrypt_decrypt_array_empty(self, db_session: Session):
        """Test that empty arrays are handled correctly."""

        user = self._create_user(
            db_session, username="user23", password=TEST_PASSWORD, tags=[]
        )

        assert user.tags == []

    def test_encrypt_decrypt_array_single_element(self, db_session: Session):
        """Test that single-element arrays are handled correctly."""

        user = self._create_user(
            db_session, username="user24", password=TEST_PASSWORD, tags=["only"]
        )

        assert user.tags == ["only"]

    def test_blind_index_hmac_stored_and_retrieved(self, db_session: Session):
        """Test that HMAC-SHA256 blind index is stored and retrieved correctly."""

        user = self._create_user(
            db_session, username="user25", password=TEST_PASSWORD, blind_index_email=TEST_EMAIL
        )

        assert user.blind_index_email is not None
        assert isinstance(user.blind_index_email, BlindIndexValue)
        assert len(user.blind_index_email) == 32

    def test_blind_index_argon2_stored_and_retrieved(self, db_session: Session):
        """Test that Argon2 blind index is stored and retrieved correctly."""

        user = self._create_user(
            db_session, username="user26", password=TEST_PASSWORD, blind_index_email_argon2=TEST_EMAIL
        )

        assert user.blind_index_email_argon2 is not None
        assert isinstance(user.blind_index_email_argon2, BlindIndexValue)
        assert len(user.blind_index_email_argon2) == 32

    def test_blind_index_none_handling(self, db_session: Session):
        """Test that None blind index values are handled correctly."""

        user = self._create_user(
            db_session, username="user27", password=TEST_PASSWORD
        )

        assert user.blind_index_email is None
        assert user.blind_index_email_argon2 is None

    def test_blind_index_deterministic_query(self, db_session: Session):
        """Test that blind index enables deterministic querying."""

        unique_email = "blind-index-query-test@example.com"

        self._create_user(
            db_session, username="user28", password=TEST_PASSWORD, blind_index_email=unique_email
        )

        # Query using the same plaintext value — SQLAlchemy's TypeDecorator
        # will hash it via process_bind_param, producing the same blind index
        found_user = db_session.query(User).filter(
            User.blind_index_email == unique_email
        ).first()

        assert found_user is not None
        assert found_user.username == "user28"

    def test_blind_index_different_emails_produce_different_indexes(self, db_session: Session):
        """Test that different emails produce different blind indexes."""

        user1 = self._create_user(
            db_session, username="user29", password=TEST_PASSWORD, blind_index_email="alice@example.com"
        )
        user2 = self._create_user(
            db_session, username="user30", password=TEST_PASSWORD, blind_index_email="bob@example.com"
        )

        assert user1.blind_index_email != user2.blind_index_email

    def test_blind_index_same_email_produces_same_index(self, db_session: Session):
        """Test that the same email produces the same blind index across rows."""

        user1 = self._create_user(
            db_session, username="user31", password=TEST_PASSWORD, blind_index_email="same@example.com"
        )
        user2 = self._create_user(
            db_session, username="user32", password=TEST_PASSWORD, blind_index_email="same@example.com"
        )

        assert user1.blind_index_email == user2.blind_index_email
