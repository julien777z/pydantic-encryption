from pydantic_encryption.integrations.sqlalchemy.hashing import SQLAlchemyHashedValue
from pydantic_encryption.types import HashedValue
from tests.dialects import TEST_DIALECT


class TestHashedValue:
    """Test ``SQLAlchemyHashedValue`` column type behavior."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyHashedValue()

    def test_hash_produces_argon2_value(self):
        """Test that hashing a string produces an Argon2 HashedValue."""

        result = self.type_adapter.hash("secret")

        assert isinstance(result, bytes)
        assert result != b"secret"

    def test_process_bind_param_hashes_value(self):
        """Test that binding a value hashes it before storage."""

        result = self.type_adapter.process_bind_param("secret", TEST_DIALECT)

        assert result is not None
        assert result != b"secret"

    def test_process_bind_param_none_returns_none(self):
        """Test that binding None returns None."""

        assert self.type_adapter.process_bind_param(None, TEST_DIALECT) is None

    def test_process_literal_param_hashes_value(self):
        """Test that a literal value is hashed rather than rendered in the clear."""

        result = self.type_adapter.process_literal_param("secret", TEST_DIALECT)

        assert isinstance(result, HashedValue)
        assert b"secret" not in bytes(result)

    def test_process_literal_param_none_returns_none(self):
        """Test that a None literal value returns None."""

        assert self.type_adapter.process_literal_param(None, TEST_DIALECT) is None

    def test_process_result_value_wraps_hashed_value(self):
        """Test that a stored hash is wrapped as a HashedValue on read."""

        result = self.type_adapter.process_result_value(b"stored-hash", TEST_DIALECT)

        assert isinstance(result, HashedValue)
        assert result == HashedValue(b"stored-hash")

    def test_process_result_value_none_returns_none(self):
        """Test that a None stored value returns None."""

        assert self.type_adapter.process_result_value(None, TEST_DIALECT) is None

    def test_python_type_matches_impl(self):
        """Test that python_type mirrors the LargeBinary impl type."""

        assert self.type_adapter.python_type is self.type_adapter.impl.python_type
