import pytest

from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter
from tests.cases import INDEX_KEY
from tests.unit.utils import ASYNC_PATHS, call_path


@pytest.mark.asyncio
@ASYNC_PATHS
class TestArgon2BlindIndexAdapter:
    """Test Argon2 blind indexing."""

    async def test_index_matches_across_paths(self, asynchronous: bool):
        """Test that a value indexes to the same digest through the sync and async paths."""

        assert await call_path(
            asynchronous,
            Argon2BlindIndexAdapter.compute_blind_index,
            Argon2BlindIndexAdapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
        ) == await call_path(
            not asynchronous,
            Argon2BlindIndexAdapter.compute_blind_index,
            Argon2BlindIndexAdapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
        )

    async def test_index_passes_through(self, asynchronous: bool):
        """Test that indexing an existing blind index returns it unchanged."""

        index = await call_path(
            asynchronous,
            Argon2BlindIndexAdapter.compute_blind_index,
            Argon2BlindIndexAdapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
        )

        assert (
            await call_path(
                asynchronous,
                Argon2BlindIndexAdapter.compute_blind_index,
                Argon2BlindIndexAdapter.async_compute_blind_index,
                index,
                INDEX_KEY,
            )
            is index
        )
