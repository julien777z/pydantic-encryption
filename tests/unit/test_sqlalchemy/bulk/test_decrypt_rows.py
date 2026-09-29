import asyncio

from pydantic_encryption.integrations.sqlalchemy import decrypt_rows
from tests.unit.test_sqlalchemy.tables import DeferPair


class TestDecryptRows:
    """Test the decrypt_rows bulk helper."""

    def test_decrypts_across_columns(self):
        """Test that every named column of every row is decrypted."""

        rows = [DeferPair.from_plaintext(f"user{i}@example.test", f"secret-{i}") for i in range(3)]

        asyncio.run(decrypt_rows(rows, "email", "secret"))

        assert [(row.email, row.secret) for row in rows] == [
            (f"user{i}@example.test", f"secret-{i}") for i in range(3)
        ]

    def test_no_rows_or_cells_is_noop(self):
        """Test that no rows, or rows with no ciphertext, decrypt without raising."""

        empty_row = DeferPair.from_plaintext(None, None)

        asyncio.run(decrypt_rows([], "email"))
        asyncio.run(decrypt_rows([empty_row], "email"))

        assert empty_row.email is None

    def test_none_cells_skipped(self):
        """Test that empty cells stay empty while their neighbours decrypt."""

        rows = [DeferPair.from_plaintext("a@example.test", None), DeferPair.from_plaintext(None, "s1")]

        asyncio.run(decrypt_rows(rows, "email", "secret"))

        assert [(row.email, row.secret) for row in rows] == [("a@example.test", None), (None, "s1")]
