import pytest

from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.types import BlindIndexValue

INDEX_KEY = b"sample-index-key"


async def compute(value: str | bytes, asynchronous: bool, salt: bytes | None = None) -> BlindIndexValue:
    """Compute a blind index through the sync or async path."""

    if asynchronous:
        return await HMACSHA256Adapter.async_compute_blind_index(value, INDEX_KEY, salt=salt)

    return HMACSHA256Adapter.compute_blind_index(value, INDEX_KEY, salt=salt)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
class TestHMACSHA256Adapter:
    """Test HMAC-SHA256 blind indexing."""

    @pytest.mark.parametrize("value", ["sample@example.test", b"sample@example.test"], ids=["str", "bytes"])
    async def test_index_is_deterministic_digest(self, asynchronous: bool, value: str | bytes):
        """Test that a value indexes to the same 32-byte digest every time, through either path."""

        index = await compute(value, asynchronous)

        assert isinstance(index, BlindIndexValue)
        assert len(index) == 32
        assert index == await compute(value, not asynchronous)

    async def test_salt_changes_index(self, asynchronous: bool):
        """Test that a salt changes the index, reproducibly, and no salt matches the default."""

        unsalted = await compute("sample", asynchronous)
        salted = await compute("sample", asynchronous, salt=b"sample-salt")

        assert salted != unsalted
        assert salted == await compute("sample", asynchronous, salt=b"sample-salt")
        assert unsalted == await compute("sample", asynchronous, salt=None)

    async def test_index_passes_through(self, asynchronous: bool):
        """Test that indexing an existing blind index returns it unchanged."""

        index = await compute("sample", asynchronous)

        assert await compute(index, asynchronous) is index
