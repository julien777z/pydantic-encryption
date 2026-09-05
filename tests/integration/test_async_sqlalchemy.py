import pytest
from sqlalchemy import inspect as sa_inspect, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from pydantic_encryption import finalize_sqlalchemy_session
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from pydantic_encryption.types import EncryptedValue

from tests.integration.database import User


class TestIntegrationAsyncFinalizeSession:
    """Test finalize_sqlalchemy_session against a real Postgres AsyncSession."""

    @pytest.mark.asyncio
    async def test_finalize_decrypts_pending_and_commits(
        self,
        async_session: AsyncSession,
        db_session: Session,
    ):
        """finalize_sqlalchemy_session should drain the pending bucket and release the pool slot."""

        db_session.add(
            User(username="async_finalize_commit", email="finalize@example.com", password="pass123")
        )
        db_session.commit()

        result = await async_session.execute(select(User).where(User.username == "async_finalize_commit"))
        user = result.scalar_one()

        # Before the drain, the raw cell is still wrapped ciphertext and the
        # session has an autobegun transaction holding a connection.
        assert isinstance(sa_inspect(user).dict["email"], EncryptedValue)
        assert async_session.in_transaction()

        await finalize_sqlalchemy_session(async_session)

        # After the drain, the plaintext has been committed on the row, the
        # pending-decrypt bucket is empty, and the transaction is closed so
        # the pooled connection has been returned.
        assert sa_inspect(user).dict["email"] == "finalize@example.com"
        assert PENDING_DECRYPT_KEY not in async_session.info
        assert not async_session.in_transaction()

    @pytest.mark.asyncio
    async def test_finalize_is_safe_on_fresh_session(self, async_session: AsyncSession):
        """finalize_sqlalchemy_session on an untouched session commits nothing and raises nothing."""

        assert not async_session.in_transaction()

        await finalize_sqlalchemy_session(async_session)

        assert not async_session.in_transaction()
        assert PENDING_DECRYPT_KEY not in async_session.info

    @pytest.mark.asyncio
    async def test_finalize_descriptor_returns_cached_plaintext_after_drain(
        self,
        async_session: AsyncSession,
        db_session: Session,
    ):
        """Test that a descriptor read returns cached plaintext once the drain has committed."""

        db_session.add(User(username="async_finalize_cache", email="cache@example.com", password="pass123"))
        db_session.commit()

        result = await async_session.execute(select(User).where(User.username == "async_finalize_cache"))
        user = result.scalar_one()

        await finalize_sqlalchemy_session(async_session)
        assert not async_session.in_transaction()

        # Attribute reads after the drain must not require a live transaction.
        assert user.email == "cache@example.com"
        assert user.username == "async_finalize_cache"

        # Accessing the descriptor did not re-open a transaction.
        assert not async_session.in_transaction()
