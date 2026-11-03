import warnings
from unittest.mock import patch

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import select
from sqlalchemy.orm import Session

from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.types import EncryptedValue
from tests.factories import User
from tests.unit.test_sqlalchemy.tables import Member, RenamedColumnRow


class TestDecryptOnAccessDescriptor:
    """Test the descriptor that decrypts an encrypted attribute when it is read."""

    def test_class_access_returns_instrumented_attribute(self, user: User):
        """Test that reading the attribute from the class returns SQLAlchemy's attribute for queries."""

        attribute = Member.first_name
        statement = select(Member).where(Member.first_name == user.first_name)

        assert not isinstance(attribute, DecryptOnAccessDescriptor)
        assert attribute.key == "first_name"
        assert "first_name" in str(statement.compile())

    def test_descriptor_exposes_wrapped_key(self):
        """Test that the descriptor exposes the wrapped attribute's column key."""

        assert Member.__dict__["first_name"].key == "first_name"

    def test_assignment_stores_on_row_state(self, user: User):
        """Test that assigning through the descriptor stores the value on the row's state."""

        member = Member(id=user.id)
        member.first_name = user.first_name

        assert sa_inspect(member).dict["first_name"] == user.first_name

    def test_deletion_removes_from_row_state(self, user: User):
        """Test that deleting through the descriptor removes the value from the row's state."""

        member = Member.from_user(user)

        del member.first_name

        assert "first_name" not in sa_inspect(member).dict

    def test_detached_read_decrypts_only_that_column(self, user: User):
        """Test that reading one column of a detached row decrypts it in place, leaving siblings sealed."""

        member = Member.from_user(user)

        assert member.first_name == user.first_name
        assert sa_inspect(member).dict["first_name"] == user.first_name
        assert isinstance(sa_inspect(member).dict["last_name"], EncryptedValue)

    def test_plaintext_reads_unchanged(self, user: User):
        """Test that values that are not ciphertext read back as they are."""

        member = Member(id=user.id, first_name=user.first_name, last_name=None)

        assert (member.id, member.first_name, member.last_name) == (user.id, user.first_name, None)

    def test_session_read_outside_greenlet_decrypts_synchronously(self, user: User):
        """Test that a session row read outside a greenlet decrypts synchronously, leaving no coroutine."""

        member = Member.from_user(user)

        with (
            patch(
                "pydantic_encryption.integrations.sqlalchemy.descriptor.object_session",
                return_value=Session(),
            ),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always")

            assert member.first_name == user.first_name

        assert not any("never awaited" in str(warning.message).lower() for warning in caught)

    def test_renamed_column_decrypts_on_read(self, sqlite_session: Session):
        """Test that reading an attribute stored under another column name returns its plaintext."""

        sqlite_session.add(RenamedColumnRow(id=1, secret="secret data"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        row = sqlite_session.get(RenamedColumnRow, 1)

        assert row is not None
        assert row.secret == "secret data"
