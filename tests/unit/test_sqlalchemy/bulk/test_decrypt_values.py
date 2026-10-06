import asyncio

import pytest

from pydantic_encryption.integrations.sqlalchemy import decrypt_values
from tests.unit.test_sqlalchemy.tables import BulkMember
from tests.unit.test_sqlalchemy.utils import encrypt_through_column


class TestDecryptValues:
    """Test the decrypt_values bulk helper for flat ciphertext iterables."""

    def test_decrypts_ciphertexts(self):
        """Test that every ciphertext in the list is decrypted in place."""

        values = [encrypt_through_column(BulkMember.__table__.c.first_name, f"user-{i}") for i in range(3)]

        assert asyncio.run(decrypt_values(values, context=BulkMember.first_name)) == [
            "user-0",
            "user-1",
            "user-2",
        ]

    def test_non_ciphertexts_pass_through(self):
        """Test that None and other non-ciphertext values keep their positions unchanged."""

        values = [
            encrypt_through_column(BulkMember.__table__.c.first_name, "a"),
            None,
            42,
            "plain",
            encrypt_through_column(BulkMember.__table__.c.first_name, "b"),
        ]

        result = asyncio.run(decrypt_values(values, context=BulkMember.first_name))

        assert result == ["a", None, 42, "plain", "b"]

    def test_empty_input(self):
        """Test that an empty list decrypts to an empty list."""

        assert asyncio.run(decrypt_values([], context=BulkMember.first_name)) == []

    def test_written_out_context(self):
        """Test that a context named directly opens what its own column sealed."""

        values = [encrypt_through_column(BulkMember.__table__.c.first_name, "a")]

        assert asyncio.run(decrypt_values(values, context="_bulk_test_member.first_name")) == ["a"]

    def test_plain_column_context_refused(self):
        """Test that asking a plain column for a context raises rather than binding nothing."""

        values = [encrypt_through_column(BulkMember.__table__.c.first_name, "a")]

        with pytest.raises(ValueError, match="does not encrypt its values"):
            asyncio.run(decrypt_values(values, context=BulkMember.id))
