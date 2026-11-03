import pytest

from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter
from pydantic_encryption.types import BlindIndexValue

INDEX_KEY = b"sample-index-key"


async def compute(value: str | bytes, asynchronous: bool) -> BlindIndexValue:
    """Compute a blind index through the sync or async path."""

    if asynchronous:
        return await Argon2BlindIndexAdapter.async_compute_blind_index(value, INDEX_KEY)

    return Argon2BlindIndexAdapter.compute_blind_index(value, INDEX_KEY)


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True], ids=["sync", "async"])
class TestArgon2BlindIndexAdapter:
    """Test Argon2 blind indexing."""

    async def test_index_matches_across_paths(self, asynchronous: bool):
        """Test that a value indexes to the same digest through the sync and async paths."""

        assert await compute("sample", asynchronous) == await compute("sample", not asynchronous)

    async def test_index_passes_through(self, asynchronous: bool):
        """Test that indexing an existing blind index returns it unchanged."""

        index = await compute("sample", asynchronous)

        assert await compute(index, asynchronous) is index
