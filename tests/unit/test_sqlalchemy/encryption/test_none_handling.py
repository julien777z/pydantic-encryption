from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue


class TestEncryptedValueNoneHandling:
    """Test ``SQLAlchemyEncryptedValue`` None handling and metadata."""

    def setup_method(self):
        """Build the column type under test."""

        self.type_adapter = SQLAlchemyEncryptedValue("tests.encrypted_column.value")

    def test_encrypt_cell_none_returns_none(self):
        """Test that encrypting None returns None without invoking the backend."""

        assert self.type_adapter.encrypt_cell(None) is None

    def test_decrypt_cell_none_returns_none(self):
        """Test that decrypting None returns None without invoking the backend."""

        assert self.type_adapter.decrypt_cell(None) is None

    def test_python_type_is_bytes(self):
        """Test that the column type reports bytes as its Python type."""

        assert self.type_adapter.python_type is bytes
