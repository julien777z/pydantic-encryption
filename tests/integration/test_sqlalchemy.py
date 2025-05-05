from typing import Final
from sqlalchemy.orm import Session
from tests.integration.database import User, UserManaged


TEST_PASSWORD: Final[str] = "pass123"
TEST_EMAIL: Final[str] = "user1@example.com"
TEST_USERNAME: Final[str] = "user1"


class TestIntegrationSQLAlchemy:
    """Test the integration with SQLAlchemy."""

    def _create_user(
        self,
        model: type[User] | type[UserManaged],
        db_session: Session,
        password: str,
    ) -> User | UserManaged:
        """Create a user."""

        user = db_session.add(
            model(
                username=TEST_USERNAME,
                email=TEST_EMAIL,
                password=password,
            )
        )

        db_session.commit()

        return user

    def test_secure_fields(self, db_session: Session):
        """Test encrypting and hashing fields with the SQLAlchemyEncryptedString and SQLAlchemyHashedString types."""

        self._create_user(User, db_session, password=TEST_PASSWORD)

        user = db_session.query(User).first()

        self._assert_correct_user(user)

    def test_secure_fields_managed(self, db_session: Session):
        """Test encrypting and hashing fields with the SecureModel and Encrypt/Hash annotations."""

        self._create_user(UserManaged, db_session, password=TEST_PASSWORD)

        user = db_session.query(UserManaged).first()

        self._assert_correct_user(user)

    def _assert_correct_user(self, user: User | UserManaged):
        """Assert that the user is correct."""

        assert user.username == TEST_USERNAME
        assert user.email == TEST_EMAIL

        assert getattr(user.password, "hashed") is True  # Hashed
        assert getattr(user.email, "encrypted") is False  # Decrypted
