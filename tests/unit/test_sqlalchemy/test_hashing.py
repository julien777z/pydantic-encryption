from sqlalchemy.engine import Dialect
from pydantic_encryption.integrations.sqlalchemy.hashing import SQLAlchemyHashedValue
from pydantic_encryption.types import HashedValue


class TestHashedValue:
    """Test ``SQLAlchemyHashedValue`` column type behavior."""

    def setup_method(self):
        """Build the column type under test."""

        self.type_adapter = SQLAlchemyHashedValue()

    def test_hash_produces_argon2_value(self):
        """Test that hashing a string produces an Argon2 HashedValue."""

        result = self.type_adapter.hash("secret")

        assert isinstance(result, bytes)
        assert result != b"secret"

    def test_process_bind_param_hashes_value(self, sqlite_dialect: Dialect):
        """Test that binding a value hashes it before storage."""

        result = self.type_adapter.process_bind_param("secret", sqlite_dialect)

        assert result is not None
        assert result != b"secret"

    def test_process_bind_param_none_returns_none(self, sqlite_dialect: Dialect):
        """Test that binding None returns None."""

        assert self.type_adapter.process_bind_param(None, sqlite_dialect) is None

    def test_process_result_value_wraps_hashed_value(self, sqlite_dialect: Dialect):
        """Test that a stored hash is wrapped as a HashedValue on read."""

        result = self.type_adapter.process_result_value(b"stored-hash", sqlite_dialect)

        assert isinstance(result, HashedValue)
        assert result == HashedValue(b"stored-hash")

    def test_process_result_value_none_returns_none(self, sqlite_dialect: Dialect):
        """Test that a None stored value returns None."""

        assert self.type_adapter.process_result_value(None, sqlite_dialect) is None

    def test_python_type_is_bytes(self):
        """Test that the column type reports bytes as its Python type."""

        assert self.type_adapter.python_type is bytes
