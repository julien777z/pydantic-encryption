import pytest

from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.types import HashedValue
from tests.cases import PLAINTEXT_IDS, PLAINTEXTS


async def hash_value(value: str | bytes | HashedValue, asynchronous: bool) -> HashedValue:
    """Hash a value through the sync or async path."""

    if asynchronous:
        return await Argon2Adapter.async_hash(value)

    return Argon2Adapter.hash(value)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
class TestArgon2Adapter:
    """Test Argon2 password hashing."""

    @pytest.mark.parametrize("value", [*PLAINTEXTS[1:], b"secret bytes"], ids=[*PLAINTEXT_IDS[1:], "bytes"])
    async def test_hash_is_salted_argon2(self, asynchronous: bool, value: str | bytes):
        """Test that a value hashes to a salted Argon2 digest that differs on every call."""

        first = await hash_value(value, asynchronous)
        second = await hash_value(value, asynchronous)

        assert isinstance(first, HashedValue)
        assert first.startswith(b"$argon2")
        assert first != second

    async def test_different_values_differ(self, asynchronous: bool):
        """Test that two values hash to different digests."""

        assert await hash_value("first secret", asynchronous) != await hash_value(
            "second secret", asynchronous
        )

    async def test_hash_passes_through(self, asynchronous: bool):
        """Test that hashing an existing hash returns it unchanged."""

        hashed = await hash_value("secret data", asynchronous)

        assert await hash_value(hashed, asynchronous) is hashed
