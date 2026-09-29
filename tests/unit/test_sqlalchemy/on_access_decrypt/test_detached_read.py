import asyncio
import warnings
from unittest.mock import patch

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session, configure_mappers

from pydantic_encryption.types import EncryptedValue
from tests.factories import User
from tests.unit.test_sqlalchemy.tables import OnAccessRow


class TestDescriptorOnDetachedRead:
    """Test that reading an encrypted attribute on a detached instance decrypts in place."""

    @classmethod
    def setup_class(cls):
        """Configure mappers before running tests in this class."""

        configure_mappers()

    def test_detached_instance_decrypts_in_place(self, user: User):
        """Test that reading an encrypted column on a detached instance returns plaintext."""

        row = OnAccessRow.from_user(user)

        assert row.first_name == user.first_name
        assert sa_inspect(row).dict["first_name"] == user.first_name

    def test_detached_read_does_not_decrypt_other_columns(self, user: User):
        """Test that reading one column on a detached row does not eagerly decrypt siblings."""

        row = OnAccessRow.from_user(user)

        assert row.first_name == user.first_name
        assert isinstance(sa_inspect(row).dict["last_name"], EncryptedValue)

    def test_other_columns_still_readable_when_plaintext(self, user: User):
        """Test that plaintext values on a detached row read back unchanged."""

        row = OnAccessRow(id=user.id, first_name=user.first_name, last_name=None)

        assert row.first_name == user.first_name
        assert row.last_name is None

    def test_plain_integer_columns_never_raise(self, user: User):
        """Test that non-encrypted columns are readable on a detached row."""

        row = OnAccessRow(id=user.id)

        assert row.id == user.id

    def test_no_greenlet_falls_back_to_sync_decrypt(self, user: User):
        """Test that a session-bound row outside a greenlet falls back to sync decrypt."""

        row = OnAccessRow.from_user(user)
        fake_session = Session()

        with patch(
            "pydantic_encryption.integrations.sqlalchemy.descriptor.object_session",
            return_value=fake_session,
        ):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                assert row.first_name == user.first_name

            assert not any("never awaited" in str(w.message).lower() for w in caught)

    def test_decrypt_method_unblocks_subsequent_reads(self, user: User):
        """Test that awaiting instance.decrypt() leaves the attribute as plaintext."""

        row = OnAccessRow.from_user(user)

        asyncio.run(row.decrypt())

        assert row.first_name == user.first_name
