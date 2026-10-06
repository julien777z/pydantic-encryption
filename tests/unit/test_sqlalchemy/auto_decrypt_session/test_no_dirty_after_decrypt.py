import asyncio

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import configure_mappers

from tests.unit.test_sqlalchemy.utils import encrypt_through_column
from tests.unit.test_sqlalchemy.tables import AutoDecryptUser


class TestNoDirtyAfterDecrypt:
    """Test that decrypted columns are not marked dirty for the next flush."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_decrypt_many_does_not_mark_column_dirty(self):
        """Test that decrypting a column does not mark it dirty for the next flush."""

        user = AutoDecryptUser(
            id=1, email=encrypt_through_column(AutoDecryptUser.__table__.c.email, "a@x.com")
        )
        state = sa_inspect(user)
        state._commit_all(state.dict)

        assert "email" not in state.committed_state

        asyncio.run(AutoDecryptUser.decrypt_many([user]))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert "email" not in state.committed_state
