import asyncio
from types import SimpleNamespace

import pytest

from pydantic_encryption.integrations.sqlalchemy import async_decrypt_rows
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


class TestDeferDecrypt:
    """Test that defer_decrypt=True skips decryption on the read path."""

    def test_defer_decrypt_returns_encrypted_value(self):
        adapter = SQLAlchemyEncryptedValue(defer_decrypt=True)
        ciphertext = adapter.process_bind_param("hello", None)
        assert ciphertext is not None

        result = adapter.process_result_value(ciphertext, None)
        assert isinstance(result, EncryptedValue)
        # defer_decrypt must NOT return plaintext
        assert result != "hello"

    def test_defer_decrypt_none_passthrough(self):
        adapter = SQLAlchemyEncryptedValue(defer_decrypt=True)
        assert adapter.process_result_value(None, None) is None

    def test_default_decrypt_returns_plaintext(self):
        adapter = SQLAlchemyEncryptedValue()
        ciphertext = adapter.process_bind_param("hello", None)
        result = adapter.process_result_value(ciphertext, None)
        assert result == "hello"


class TestAsyncDecryptRows:
    """Test the async_decrypt_rows bulk helper."""

    def _make_ciphertext(self, value):
        return SQLAlchemyEncryptedValue(defer_decrypt=False).process_bind_param(value, None)

    def test_async_decrypt_rows_fernet(self):
        # Build 3 fake rows with 2 encrypted columns each.
        rows = [
            SimpleNamespace(
                email=EncryptedValue(self._make_ciphertext(f"user{i}@example.com")),
                secret=EncryptedValue(self._make_ciphertext(f"secret-{i}")),
            )
            for i in range(3)
        ]

        asyncio.run(async_decrypt_rows(rows, "email", "secret"))

        for i, row in enumerate(rows):
            assert row.email == f"user{i}@example.com"
            assert row.secret == f"secret-{i}"

    def test_async_decrypt_rows_empty(self):
        asyncio.run(async_decrypt_rows([], "email"))  # no error
        asyncio.run(async_decrypt_rows([SimpleNamespace(email=None)], "email"))  # no error

    def test_async_decrypt_rows_skips_none_cells(self):
        rows = [
            SimpleNamespace(email=EncryptedValue(self._make_ciphertext("a@x.com")), secret=None),
            SimpleNamespace(email=None, secret=EncryptedValue(self._make_ciphertext("s1"))),
        ]

        asyncio.run(async_decrypt_rows(rows, "email", "secret"))

        assert rows[0].email == "a@x.com"
        assert rows[0].secret is None
        assert rows[1].email is None
        assert rows[1].secret == "s1"

    def test_async_decrypt_rows_respects_concurrency(self):
        rows = [
            SimpleNamespace(email=EncryptedValue(self._make_ciphertext(f"u{i}@x.com")))
            for i in range(5)
        ]

        asyncio.run(async_decrypt_rows(rows, "email", concurrency=2))

        for i, row in enumerate(rows):
            assert row.email == f"u{i}@x.com"
