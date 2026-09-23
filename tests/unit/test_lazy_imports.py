import importlib

import pytest

from pydantic_encryption import adapters, integrations
from pydantic_encryption.lazy import require_optional_dependency


class TestRequireOptionalDependency:
    """Test the import that names the extra to install when a dependency is absent."""

    def test_an_installed_dependency_is_returned(self):
        """Test that an installed module is handed back to the caller."""

        assert require_optional_dependency("json", "json").__name__ == "json"

    def test_an_absent_dependency_names_the_extra_to_install(self):
        """Test that a missing module raises an error naming the extra that provides it."""

        with pytest.raises(ImportError, match=r"pydantic-encryption\[imaginary\]"):
            require_optional_dependency("no_such_module_exists", "imaginary")


class TestLazySubmodules:
    """Test the submodules that are imported only when they are first read."""

    @pytest.mark.parametrize(
        "package, attribute",
        [
            ("pydantic_encryption.adapters.encryption", "aws"),
            ("pydantic_encryption.integrations", "sqlalchemy"),
        ],
        ids=["aws-backend", "sqlalchemy-integration"],
    )
    def test_a_lazy_submodule_imports_on_first_read(
        self, package: str, attribute: str, monkeypatch: pytest.MonkeyPatch
    ):
        """Test that reading a lazy submodule imports it rather than recurring into the lookup."""

        module = importlib.import_module(package)
        monkeypatch.delattr(module, attribute, raising=False)

        assert getattr(module, attribute).__name__ == f"{package}.{attribute}"

    def test_the_aws_backend_is_reachable_by_attribute(self):
        """Test that the AWS backend answers through the package it hangs from."""

        assert adapters.encryption.aws.DATA_KEY_SPEC == "AES_256"

    def test_an_unknown_backend_attribute_is_refused(self):
        """Test that reading a backend that does not exist raises rather than importing something."""

        with pytest.raises(AttributeError, match="no attribute"):
            adapters.encryption.mystery

    def test_the_sqlalchemy_integration_is_reachable_by_attribute(self):
        """Test that the SQLAlchemy integration imports on first read."""

        assert integrations.sqlalchemy.DeferredDecryptMixin is not None

    def test_an_unknown_integration_attribute_is_refused(self):
        """Test that reading an integration that does not exist raises rather than importing something."""

        with pytest.raises(AttributeError, match="no attribute"):
            integrations.mystery
