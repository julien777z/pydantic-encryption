import asyncio
from unittest.mock import patch

from sqlalchemy import inspect as sa_inspect

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.integrations.sqlalchemy import decrypt_rows
from pydantic_encryption.types import EncryptedValue
from tests.factories import User
from tests.unit.test_sqlalchemy.tables import OnAccessBytesRow, OnAccessRow


class TestBatchAcrossSiblings:
    """Test that the async batch helper decrypts one column across every row in parallel."""

    def test_batches_across_every_row(self, users_batch: list[User]):
        """Test that batch-decrypt touches only the requested column across all rows."""

        rows = [OnAccessRow.from_user(user) for user in users_batch]

        asyncio.run(decrypt_rows(rows, "first_name"))

        for row, user in zip(rows, users_batch):
            assert sa_inspect(row).dict["first_name"] == user.first_name
            assert isinstance(sa_inspect(row).dict["last_name"], EncryptedValue)

    def test_skips_rows_whose_column_is_already_decrypted(
        self,
        user: User,
        other_user: User,
    ):
        """Test that already-decrypted bytes-typed columns are not re-decrypted."""

        row_a = OnAccessBytesRow.from_user(user)
        row_b = OnAccessBytesRow.from_user(other_user)

        asyncio.run(decrypt_rows([row_a], "payload"))

        assert sa_inspect(row_a).dict["payload"] == user.payload

        asyncio.run(decrypt_rows([row_a, row_b], "payload"))

        assert sa_inspect(row_a).dict["payload"] == user.payload
        assert sa_inspect(row_b).dict["payload"] == other_user.payload

    def test_decrypt_call_count_equals_row_count(
        self,
        user: User,
        other_user: User,
    ):
        """Test that one decrypt call is issued per row in the batch."""

        rows = [OnAccessRow.from_user(user), OnAccessRow.from_user(other_user)]

        call_count = {"n": 0}

        original_decrypt = FernetAdapter.async_decrypt

        async def counting_decrypt(ciphertext, *, key=None, associated_data):
            call_count["n"] += 1

            return await original_decrypt(ciphertext, key=key, associated_data=associated_data)

        with patch.object(FernetAdapter, "async_decrypt", side_effect=counting_decrypt):
            asyncio.run(decrypt_rows(rows, "first_name"))

        assert call_count["n"] == 2
