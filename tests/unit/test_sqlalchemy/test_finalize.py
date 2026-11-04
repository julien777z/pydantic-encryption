import pytest
from sqlalchemy import inspect as sa_inspect

from pydantic_encryption.integrations.sqlalchemy import finalize_sqlalchemy_session
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from pydantic_encryption.types import EncryptedValue
from tests.unit.test_sqlalchemy.tables import SecretRow
from tests.unit.test_sqlalchemy.utils import RecordingAsyncSession


@pytest.mark.asyncio
class TestFinalizeSession:
    """Test that finalizing a session commits any open transaction, then decrypts its pending cells."""

    @pytest.mark.parametrize(("in_transaction", "commits"), [(True, 1), (False, 0)], ids=["open", "closed"])
    async def test_pending_cells_decrypted(self, in_transaction: bool, commits: int):
        """Test that pending cells are decrypted, committing only when a transaction is open."""

        row = SecretRow.sealed("secret data", id=1)
        session = RecordingAsyncSession(in_transaction=in_transaction, pending=[row])

        await finalize_sqlalchemy_session(session)

        assert sa_inspect(row).dict["secret"] == "secret data"
        assert PENDING_DECRYPT_KEY not in session.info
        assert session.commit_calls == commits

    async def test_commit_runs_before_decrypting(self):
        """Test that the commit releasing the connection runs while the pending cells are still sealed."""

        row = SecretRow.sealed("secret data", id=1)
        session = RecordingAsyncSession(in_transaction=True, pending=[row], watched=(row, "secret"))

        await finalize_sqlalchemy_session(session)

        assert isinstance(session.watched_at_commit, EncryptedValue)
        assert sa_inspect(row).dict["secret"] == "secret data"
