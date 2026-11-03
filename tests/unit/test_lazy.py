import importlib

import pytest

from pydantic_encryption.integrations.sqlalchemy import finalize_sqlalchemy_session
from pydantic_encryption.lazy import require_optional_dependency


class TestLazyImports:
    """Test the optional dependencies and submodules that are imported only when first needed."""

    def test_installed_dependency_returned(self):
        """Test that an installed module is handed back to the caller."""

        assert require_optional_dependency("json", "json").__name__ == "json"

    def test_absent_dependency_names_extra_to_install(self):
        """Test that a missing module raises an error naming the extra that provides it."""

        with pytest.raises(ImportError, match=r"pydantic-encryption\[imaginary\]"):
            require_optional_dependency("no_such_module_exists", "imaginary")

    @pytest.mark.parametrize(
        ("package", "attribute"),
        [
            ("pydantic_encryption.adapters.encryption", "aws"),
            ("pydantic_encryption.integrations", "sqlalchemy"),
        ],
        ids=["aws-backend", "sqlalchemy-integration"],
    )
    def test_submodule_imports_on_first_read(
        self, package: str, attribute: str, monkeypatch: pytest.MonkeyPatch
    ):
        """Test that reading a lazy submodule imports it rather than recurring into the lookup."""

        module = importlib.import_module(package)
        monkeypatch.delattr(module, attribute, raising=False)

        assert getattr(module, attribute).__name__ == f"{package}.{attribute}"

    def test_top_level_helper_resolves_lazily(self, monkeypatch: pytest.MonkeyPatch):
        """Test that the package exports the SQLAlchemy finalize helper, importing it on first read."""

        package = importlib.import_module("pydantic_encryption")
        monkeypatch.delitem(package.__dict__, "finalize_sqlalchemy_session", raising=False)

        assert "finalize_sqlalchemy_session" in package.__all__
        assert package.finalize_sqlalchemy_session is finalize_sqlalchemy_session

    @pytest.mark.parametrize(
        "package",
        ["pydantic_encryption.adapters.encryption", "pydantic_encryption.integrations"],
        ids=["backends", "integrations"],
    )
    def test_unknown_attribute_refused(self, package: str):
        """Test that reading a submodule that does not exist raises rather than importing something."""

        with pytest.raises(AttributeError, match="no attribute"):
            importlib.import_module(package).__getattr__("mystery")
