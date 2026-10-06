import asyncio

import pytest
from cryptography.fernet import InvalidToken
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.integrations.sqlalchemy import decrypt_rows
from tests.unit.test_sqlalchemy.tables import DeferPair
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class TestCrossColumnCiphertext:
    """Test that a value written through one column cannot be read through another."""

    @classmethod
    def setup_class(cls):
        """Configure the mappers the rows are read through."""

        configure_mappers()

    def test_moved_ciphertext_refused(self):
        """Test that a cell holding another column's ciphertext raises instead of decrypting."""

        row = DeferPair(secret=encrypt_through_column(DeferPair.__table__.c.email, "a@example.test"))

        with pytest.raises(BaseExceptionGroup) as raised:
            asyncio.run(decrypt_rows([row], "secret"))

        assert raised.group_contains(InvalidToken)
