from pydantic_encryption.integrations.sqlalchemy.hashing import SQLAlchemyHashedValue
from pydantic_encryption.types import HashedValue


class LiteralProcessorDialect:
    """Dialect stub exposing the ``literal_processor`` hook used by literal binds."""

    def literal_processor(self, impl):
        """Return a processor that renders a value as a quoted literal string."""

        def process(value: bytes) -> str:
            return repr(value)

        return process


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

        result = self.type_adapter.process_bind_param("secret", None)

        assert result is not None
        assert result != b"secret"

    def test_process_bind_param_none_returns_none(self):
        """Test that binding None returns None."""

        assert self.type_adapter.process_bind_param(None, None) is None

    def test_process_literal_param_hashes_value(self):
        """Test that a literal value is hashed and rendered through the dialect."""

        result = self.type_adapter.process_literal_param("secret", LiteralProcessorDialect())

        assert result is not None
        assert "secret" not in str(result)

    def test_process_literal_param_none_returns_none(self):
        """Test that a None literal value returns None."""

        assert self.type_adapter.process_literal_param(None, LiteralProcessorDialect()) is None

    def test_process_result_value_wraps_hashed_value(self):
        """Test that a stored hash is wrapped as a HashedValue on read."""

        result = self.type_adapter.process_result_value(b"stored-hash", None)

        assert isinstance(result, HashedValue)
        assert result == HashedValue(b"stored-hash")

    def test_process_result_value_none_returns_none(self):
        """Test that a None stored value returns None."""

        assert self.type_adapter.process_result_value(None, None) is None

    def test_python_type_matches_impl(self):
        """Test that python_type mirrors the LargeBinary impl type."""

        assert self.type_adapter.python_type is self.type_adapter.impl.python_type
