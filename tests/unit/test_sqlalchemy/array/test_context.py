from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyPGEncryptedArray


class TestArrayContext:
    """Test that an encrypted array binds its elements to the column's context."""

    def test_element_type_carries_context(self):
        """Test that the element type is bound to the context the array was given."""

        assert SQLAlchemyPGEncryptedArray("users.tags")._element_type.context == b"users.tags"

    def test_cache_key_distinguishes_contexts(self):
        """Test that two arrays with different contexts do not share a statement cache key."""

        first = SQLAlchemyPGEncryptedArray("users.tags")
        second = SQLAlchemyPGEncryptedArray("records.tags")

        assert first._static_cache_key != second._static_cache_key
