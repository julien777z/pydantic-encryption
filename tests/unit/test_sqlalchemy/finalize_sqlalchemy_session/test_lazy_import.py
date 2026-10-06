import importlib

import pydantic_encryption
from pydantic_encryption.integrations.sqlalchemy import finalize_sqlalchemy_session


class TestFinalizeSessionLazyImport:
    """Test that finalize_sqlalchemy_session is re-exported from the top-level package via __getattr__."""

    def test_top_level_attribute_resolves_to_helper(self):
        """Test that the package attribute resolves lazily to the SQLAlchemy helper."""

        cached = getattr(pydantic_encryption, "__dict__", {}).pop("finalize_sqlalchemy_session", None)
        try:
            resolved = pydantic_encryption.finalize_sqlalchemy_session
        finally:
            if cached is not None:
                pydantic_encryption.__dict__["finalize_sqlalchemy_session"] = cached

        assert resolved is finalize_sqlalchemy_session

    def test_top_level_attribute_listed_in_all(self):
        """Test that the package lists the helper in __all__."""

        module = importlib.import_module("pydantic_encryption")
        assert "finalize_sqlalchemy_session" in module.__all__
