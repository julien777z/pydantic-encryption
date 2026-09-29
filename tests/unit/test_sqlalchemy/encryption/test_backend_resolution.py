import pytest

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue


class TestBackendResolution:
    """Test ``SQLAlchemyEncryptedValue.backend`` configuration handling."""

    def test_backend_returns_configured_adapter(self):
        """Test that backend returns the adapter configured by ENCRYPTION_METHOD."""

        assert SQLAlchemyEncryptedValue.backend() is FernetAdapter

    def test_backend_raises_when_encryption_method_unset(self, monkeypatch):
        """Test that backend raises a ValueError when ENCRYPTION_METHOD is unset."""

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            SQLAlchemyEncryptedValue.backend()
