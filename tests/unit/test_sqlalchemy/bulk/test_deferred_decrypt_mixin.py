import asyncio

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

from tests.unit.test_sqlalchemy.tables import BulkMember, BulkOrg, RenamedColumnRow
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class TestDeferredDecryptMixin:
    """Test the DeferredDecryptMixin decrypt() and decrypt_many() helpers."""

    def test_nothing_to_decrypt_is_noop(self):
        """Test that decrypting None or an empty list completes without raising."""

        assert asyncio.run(BulkMember.decrypt_many(None)) is None
        assert asyncio.run(BulkMember.decrypt_many([])) is None

    def test_instance_decrypt(self):
        """Test that decrypt() restores every column of the instance and returns it."""

        member = BulkMember(
            id=1,
            first_name=encrypt_through_column(BulkMember.__table__.c.first_name, "first"),
            last_name=encrypt_through_column(BulkMember.__table__.c.last_name, "last"),
        )

        returned = asyncio.run(member.decrypt())

        assert returned is member
        assert (member.first_name, member.last_name) == ("first", "last")

    def test_decrypt_many(self):
        """Test that decrypt_many() restores every column of every instance given, in any iterable."""

        members = [
            BulkMember(
                id=i,
                first_name=encrypt_through_column(BulkMember.__table__.c.first_name, f"First{i}"),
                last_name=encrypt_through_column(BulkMember.__table__.c.last_name, f"Last{i}"),
            )
            for i in range(3)
        ]

        asyncio.run(BulkMember.decrypt_many(member for member in members))

        assert [(m.first_name, m.last_name) for m in members] == [(f"First{i}", f"Last{i}") for i in range(3)]

    def test_none_cells_skipped(self):
        """Test that empty cells stay empty while their neighbours decrypt."""

        member = BulkMember(
            id=1,
            first_name=encrypt_through_column(BulkMember.__table__.c.first_name, "first"),
            last_name=None,
        )
        empty_member = BulkMember(id=2, first_name=None, last_name=None)

        asyncio.run(BulkMember.decrypt_many([member, empty_member]))

        assert (member.first_name, member.last_name) == ("first", None)
        assert (empty_member.first_name, empty_member.last_name) == (None, None)

    def test_walks_loaded_relationships(self):
        """Test that decrypting a parent decrypts the loaded children it holds."""

        org = BulkOrg(id=1, name="sample org")
        member = BulkMember(
            id=1,
            first_name=encrypt_through_column(BulkMember.__table__.c.first_name, "first"),
            last_name=None,
        )
        org.members = [member]

        asyncio.run(org.decrypt())

        assert member.first_name == "first"

    def test_renamed_column_decrypted(self, sqlite_session: Session):
        """Test that an attribute stored under another column name is decrypted in bulk."""

        sqlite_session.add(RenamedColumnRow(id=1, secret="sealed value"))
        sqlite_session.commit()
        sqlite_session.expunge_all()

        row = sqlite_session.get(RenamedColumnRow, 1)

        assert row is not None

        asyncio.run(RenamedColumnRow.decrypt_many([row]))

        assert sa_inspect(row).dict["secret"] == "sealed value"
