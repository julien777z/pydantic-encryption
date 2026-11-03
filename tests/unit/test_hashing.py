from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import HashedValue
from tests.factories import SampleRecord


class TestUnitHashing:
    """Test basic functionality of pydantic-encryption hashing."""

    def test_hash_field(self, sample: SampleRecord):
        """Test hashing fields with Hash annotation."""
        assert sample.name is not None
        assert isinstance(sample.password, HashedValue)

    def test_double_hash_fails(self, sample: SampleRecord):
        """Test double hashing returns same value."""
        old_password = sample.password

        sample.password = Argon2Adapter.hash(sample.password)

        assert sample.password == old_password

    def test_hash_multiple_values(self, samples: list[SampleRecord]):
        """Test hashing multiple values with batch."""
        for sample in samples:
            assert isinstance(sample.password, HashedValue)
