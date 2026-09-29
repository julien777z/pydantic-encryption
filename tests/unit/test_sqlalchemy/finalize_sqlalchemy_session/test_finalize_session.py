import asyncio
from collections import defaultdict
from unittest.mock import patch
from weakref import WeakSet

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.integrations.sqlalchemy import finalize_sqlalchemy_session
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from tests.unit.test_sqlalchemy.utils import RecordingAsyncSession, encrypt_through_column
from tests.unit.test_sqlalchemy.tables import FinalizeUser


class TestFinalizeSession:
    """Test the finalize_sqlalchemy_session helper that drains pending decrypts and commits."""

    @classmethod
    def setup_class(cls):
        """Configure the mappers the rows are read through."""

        configure_mappers()

    def test_drains_pending_and_commits_when_in_transaction(self):
        """Test that an open transaction is committed and the pending cells decrypted."""

        session = RecordingAsyncSession(in_transaction=True)
        user = FinalizeUser(id=1, email=encrypt_through_column(FinalizeUser.__table__.c.email, "a@x.com"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[FinalizeUser].add(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(finalize_sqlalchemy_session(session))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert PENDING_DECRYPT_KEY not in session.info
        assert session.commit_calls == 1

    def test_skips_commit_when_not_in_transaction(self):
        """Test that no commit is issued without an open transaction."""

        session = RecordingAsyncSession(in_transaction=False)

        asyncio.run(finalize_sqlalchemy_session(session))

        assert session.commit_calls == 0

    def test_drains_pending_without_commit_when_not_in_transaction(self):
        """Test that pending cells are decrypted without a commit when no transaction is open."""

        session = RecordingAsyncSession(in_transaction=False)
        user = FinalizeUser(id=1, email=encrypt_through_column(FinalizeUser.__table__.c.email, "b@x.com"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[FinalizeUser].add(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(finalize_sqlalchemy_session(session))

        assert sa_inspect(user).dict["email"] == "b@x.com"
        assert PENDING_DECRYPT_KEY not in session.info
        assert session.commit_calls == 0

    def test_commits_before_running_bulk_decrypt(self):
        """Test that commit (releasing the pool slot) runs before the KMS-bound bulk decrypt."""

        events: list[str] = []

        class _RecordingSession(RecordingAsyncSession):
            """Session recording when its commit runs."""

            async def commit(self) -> None:
                """Record the commit before counting it."""

                events.append("commit")
                await super().commit()

        async def _recording_bulk_decrypt(_entities: object) -> None:
            """Record when the bulk decrypt runs."""

            events.append("bulk_decrypt")

        session = _RecordingSession(in_transaction=True)
        user = FinalizeUser(id=1, email=encrypt_through_column(FinalizeUser.__table__.c.email, "c@x.com"))

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[FinalizeUser].add(user)
        session.info[PENDING_DECRYPT_KEY] = bucket

        with patch(
            "pydantic_encryption.integrations.sqlalchemy.bulk.bulk_decrypt_entities",
            _recording_bulk_decrypt,
        ):
            asyncio.run(finalize_sqlalchemy_session(session))

        assert events == ["commit", "bulk_decrypt"]
        assert PENDING_DECRYPT_KEY not in session.info
