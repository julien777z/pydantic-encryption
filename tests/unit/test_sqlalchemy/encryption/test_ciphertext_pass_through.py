from sqlalchemy.engine import Dialect
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue
from pydantic_encryption.types import EncryptedValue


class TestEncryptionIdempotency:
    """Test that already-encrypted values are not re-encrypted."""

    def setup_method(self):
        """Build the column type under test."""

        self.type_adapter = SQLAlchemyEncryptedValue("tests.encrypted_column.value")

    def test_encrypt_cell_passes_ciphertext_through(self):
        """Test that encrypting a ciphertext again returns it unchanged."""

        encrypted = self.type_adapter.encrypt_cell("hello")
        double_encrypted = self.type_adapter.encrypt_cell(encrypted)

        assert encrypted == double_encrypted

    def test_bind_passes_ciphertext_through(self, sqlite_dialect: Dialect):
        """Test that binding a ciphertext again stores it unchanged."""

        encrypted = self.type_adapter.process_bind_param("hello", sqlite_dialect)

        assert encrypted is not None

        double_encrypted = self.type_adapter.process_bind_param(EncryptedValue(encrypted), sqlite_dialect)

        assert encrypted == double_encrypted
