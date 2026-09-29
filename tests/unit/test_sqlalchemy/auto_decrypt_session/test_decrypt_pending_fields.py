import asyncio
from collections import defaultdict
from weakref import WeakSet

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession

from pydantic_encryption.integrations.sqlalchemy import decrypt_pending_fields
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from tests.unit.test_sqlalchemy.utils import encrypt_through_column
from tests.unit.test_sqlalchemy.tables import AutoDecryptBlob, AutoDecryptUser


class TestDecryptPendingFields:
    """Test that decrypt_pending_fields drains the session bucket across every pending class."""

    def test_drain_decrypts_every_pending_class(self):
        """Test that the drain decrypts the pending cells of every class."""

        session = AsyncSession()
        user = AutoDecryptUser(
            id=1, email=encrypt_through_column(AutoDecryptUser.__table__.c.email, "a@x.com")
        )
        blob = AutoDecryptBlob(
            id=1, payload=encrypt_through_column(AutoDecryptBlob.__table__.c.payload, b"shh")
        )

        bucket: dict[type, WeakSet] = defaultdict(WeakSet)
        bucket[AutoDecryptUser].add(user)
        bucket[AutoDecryptBlob].add(blob)
        session.info[PENDING_DECRYPT_KEY] = bucket

        asyncio.run(decrypt_pending_fields(session))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert sa_inspect(blob).dict["payload"] == b"shh"
        assert PENDING_DECRYPT_KEY not in session.info

    def test_drain_noop_when_bucket_empty(self):
        """Test that draining a session with no bucket leaves it without one."""

        session = AsyncSession()

        asyncio.run(decrypt_pending_fields(session))

        assert PENDING_DECRYPT_KEY not in session.info
