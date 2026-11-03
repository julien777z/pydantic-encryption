import pytest

from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.types import BlindIndexValue
from tests.cases import INDEX_KEY
from tests.unit.utils import ASYNC_PATHS, call_path


@pytest.mark.asyncio
@ASYNC_PATHS
class TestHMACSHA256Adapter:
    """Test HMAC-SHA256 blind indexing."""

    @pytest.mark.parametrize("value", ["sample@example.test", b"sample@example.test"], ids=["str", "bytes"])
    async def test_index_is_deterministic_digest(self, asynchronous: bool, value: str | bytes):
        """Test that a value indexes to the same 32-byte digest every time, through either path."""

        index = await call_path(
            asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            value,
            INDEX_KEY,
        )

        assert isinstance(index, BlindIndexValue)
        assert len(index) == 32
        assert index == await call_path(
            not asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            value,
            INDEX_KEY,
        )

    async def test_salt_changes_index(self, asynchronous: bool):
        """Test that a salt changes the index, reproducibly, and no salt matches the default."""

        unsalted = await call_path(
            asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
        )
        salted = await call_path(
            asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
            salt=b"sample-salt",
        )

        assert salted != unsalted
        assert salted == await call_path(
            asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
            salt=b"sample-salt",
        )
        assert unsalted == await call_path(
            asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
            salt=None,
        )

    async def test_index_passes_through(self, asynchronous: bool):
        """Test that indexing an existing blind index returns it unchanged."""

        index = await call_path(
            asynchronous,
            HMACSHA256Adapter.compute_blind_index,
            HMACSHA256Adapter.async_compute_blind_index,
            "sample",
            INDEX_KEY,
        )

        assert (
            await call_path(
                asynchronous,
                HMACSHA256Adapter.compute_blind_index,
                HMACSHA256Adapter.async_compute_blind_index,
                index,
                INDEX_KEY,
            )
            is index
        )
