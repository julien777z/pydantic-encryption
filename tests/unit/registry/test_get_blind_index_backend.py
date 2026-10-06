import pytest

from pydantic_encryption.adapters import registry
from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.types import BlindIndexMethod


class TestGetBlindIndexBackend:
    """Test ``get_blind_index_backend`` resolution."""

    def test_registered_backend_returned(self):
        """Test that a registered blind index backend is returned."""

        assert registry.get_blind_index_backend(BlindIndexMethod.HMAC_SHA256) is HMACSHA256Adapter

    def test_unregistered_method_refused(self, monkeypatch: pytest.MonkeyPatch):
        """Test that a method with no registered backend raises."""

        monkeypatch.setattr(registry, "blind_index_backends", {})

        with pytest.raises(ValueError, match="No blind index backend registered"):
            registry.get_blind_index_backend(BlindIndexMethod.HMAC_SHA256)
