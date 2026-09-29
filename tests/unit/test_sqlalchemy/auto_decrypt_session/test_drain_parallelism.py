import asyncio
from collections import defaultdict
from unittest.mock import patch
from weakref import WeakSet

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.integrations.sqlalchemy import decrypt_pending_fields
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY
from tests.unit.test_sqlalchemy.utils import encrypt_through_column
from tests.unit.test_sqlalchemy.tables import AutoDecryptBlob, AutoDecryptUser


class TestDrainParallelism:
    """Test that decrypt_pending_fields fans out every class's cells under one TaskGroup."""

    @classmethod
    def setup_class(cls):
        configure_mappers()

    def test_drain_dispatches_cells_across_classes_in_parallel(self):
        """Test that the drain decrypts every class's cells concurrently."""

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

        live_overlap = 0
        peak_overlap = 0
        original_decrypt = FernetAdapter.decrypt

        async def overlapping_async_decrypt(ciphertext, *, key=None, associated_data):
            nonlocal live_overlap, peak_overlap
            live_overlap += 1
            peak_overlap = max(peak_overlap, live_overlap)
            try:
                await asyncio.sleep(0)
                return original_decrypt(ciphertext, key=key, associated_data=associated_data)
            finally:
                live_overlap -= 1

        with patch.object(FernetAdapter, "async_decrypt", side_effect=overlapping_async_decrypt):
            asyncio.run(decrypt_pending_fields(session))

        assert sa_inspect(user).dict["email"] == "a@x.com"
        assert sa_inspect(blob).dict["payload"] == b"shh"
        assert peak_overlap >= 2, (
            "expected at least two decrypts to be in flight together across classes; "
            f"observed peak overlap {peak_overlap}"
        )
