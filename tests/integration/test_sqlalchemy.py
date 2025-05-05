from typing import Final
from sqlalchemy.orm import Session
from tests.integration.database import User


TEST_PASSWORD: Final[str] = "pass123"
TEST_EMAIL: Final[str] = "user1@example.com"
TEST_USERNAME: Final[str] = "user1"


class TestIntegrationSQLAlchemy:
    """Test the integration with SQLAlchemy."""

    def _create_user(self, db_session: Session, password: str) -> User:
        """Create a user."""

        user = db_session.add(
            User(
                username=TEST_USERNAME,
                email=TEST_EMAIL,
                password=password,
            )
        )

        db_session.commit()

        return user

    def test_secure_fields(self, db_session: Session):
        """Test encrypting and hashing fields with the SQLAlchemyEncryptedString and SQLAlchemyHashedString types."""

        self._create_user(db_session, password=TEST_PASSWORD)

        user = db_session.query(User).first()

        self._assert_correct_user(user)

    def _assert_correct_user(self, user: User):
        """Assert that the user is correct."""

        assert user.username == TEST_USERNAME
        assert user.email == TEST_EMAIL

        assert getattr(user.password, "hashed") is True  # Hashed
        assert getattr(user.email, "encrypted") is False  # Decrypted
