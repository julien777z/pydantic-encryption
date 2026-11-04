import pytest

from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import HashedValue
from tests.cases import PLAINTEXT_IDS, PLAINTEXTS
from tests.unit.utils import ASYNC_PATHS, call_path


@pytest.mark.asyncio
@ASYNC_PATHS
class TestArgon2Adapter:
    """Test Argon2 password hashing."""

    @pytest.mark.parametrize("value", [*PLAINTEXTS[1:], b"secret bytes"], ids=[*PLAINTEXT_IDS[1:], "bytes"])
    async def test_hash_is_salted_argon2(self, asynchronous: bool, value: str | bytes):
        """Test that a value hashes to a salted Argon2 digest that differs on every call."""

        first = await call_path(asynchronous, Argon2Adapter.hash, Argon2Adapter.async_hash, value)
        second = await call_path(asynchronous, Argon2Adapter.hash, Argon2Adapter.async_hash, value)

        assert isinstance(first, HashedValue)
        assert first.startswith(b"$argon2")
        assert first != second

    async def test_different_values_differ(self, asynchronous: bool):
        """Test that two values hash to different digests."""

        assert await call_path(
            asynchronous, Argon2Adapter.hash, Argon2Adapter.async_hash, "first secret"
        ) != await call_path(asynchronous, Argon2Adapter.hash, Argon2Adapter.async_hash, "second secret")

    async def test_hash_passes_through(self, asynchronous: bool):
        """Test that hashing an existing hash returns it unchanged."""

        hashed = await call_path(asynchronous, Argon2Adapter.hash, Argon2Adapter.async_hash, "secret data")

        assert await call_path(asynchronous, Argon2Adapter.hash, Argon2Adapter.async_hash, hashed) is hashed
