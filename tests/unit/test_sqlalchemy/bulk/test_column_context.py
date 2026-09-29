import pytest
from sqlalchemy.orm import configure_mappers

from pydantic_encryption.integrations.sqlalchemy.bulk import column_context
from tests.unit.test_sqlalchemy.tables import ArrayRow, BulkOrg, DeferPair


class TestColumnContext:
    """Test that column_context resolves the associated data a column binds its cells to."""

    @classmethod
    def setup_class(cls):
        """Configure the mappers the rows are read through."""

        configure_mappers()

    def test_encrypted_column(self):
        """Test that an encrypted column reports the context its own type carries."""

        assert column_context(DeferPair(id=1), "email") == b"_defer_pair.email"

    def test_encrypted_array_column(self):
        """Test that an encrypted array column reports its element type's context."""

        assert column_context(ArrayRow(id=1), "tags") == b"_array_row.tags"

    def test_plain_column_refused(self):
        """Test that a column binding no context raises instead of decrypting unbound."""

        with pytest.raises(ValueError, match="does not encrypt its values"):
            column_context(BulkOrg(id=1, name="sample org"), "name")
