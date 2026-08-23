import pytest

from pydantic_encryption.adapters import registry
from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.types import BlindIndexMethod, EncryptionMethod


class TestGetEncryptionBackend:
    """Test ``get_encryption_backend`` resolution and lazy loading."""

    def test_returns_eagerly_registered_backend(self, unregistered_method: EncryptionMethod):
        """Test that an eagerly registered backend is returned without locking."""

        assert registry.get_encryption_backend(EncryptionMethod.FERNET) is FernetAdapter

    def test_lazy_factory_is_invoked_and_cached(self, unregistered_method: EncryptionMethod):
        """Test that a lazy factory is invoked under the lock, cached, and removed from factories."""

        method = unregistered_method
        calls: list[int] = []

        def factory() -> type:
            calls.append(1)
            return FernetAdapter

        registry.register_encryption_backend_lazy(method, factory)

        assert method not in registry.encryption_backends
        assert registry.get_encryption_backend(method) is FernetAdapter
        assert registry.encryption_backends[method] is FernetAdapter
        assert method not in registry.encryption_factories

        assert registry.get_encryption_backend(method) is FernetAdapter
        assert calls == [1]

    def test_cached_backend_short_circuits_inside_lock(self, unregistered_method: EncryptionMethod):
        """Test that a backend cached under the lock is returned without re-invoking the factory."""

        method = unregistered_method

        def factory() -> type:
            raise AssertionError("factory must not be called when backend is cached")

        registry.register_encryption_backend_lazy(method, factory)
        registry.encryption_backends[method] = FernetAdapter

        assert registry.get_encryption_backend(method) is FernetAdapter

    def test_inside_lock_double_check_returns_concurrently_populated_backend(
        self, monkeypatch, unregistered_method: EncryptionMethod
    ):
        """Test that the inside-lock double-check returns a backend populated after the outer check."""

        method = unregistered_method

        def factory() -> type:
            raise AssertionError("factory must not be called once the backend is populated")

        registry.register_encryption_backend_lazy(method, factory)

        class PopulateOnLock:
            """Lock stand-in that simulates another thread caching the backend before lock entry."""

            def __enter__(self) -> "PopulateOnLock":
                registry.encryption_backends[method] = FernetAdapter

                return self

            def __exit__(self, *exc_info) -> None:
                return None

        monkeypatch.setattr(registry, "registry_lock", PopulateOnLock())

        assert method not in registry.encryption_backends

        assert registry.get_encryption_backend(method) is FernetAdapter

    def test_unknown_method_raises_value_error(self, unregistered_method: EncryptionMethod):
        """Test that an unregistered method raises a ValueError."""

        method = unregistered_method

        with pytest.raises(ValueError, match="No encryption backend registered"):
            registry.get_encryption_backend(method)

    def test_failing_factory_stays_retryable(self, unregistered_method: EncryptionMethod):
        """Test that a failing factory is not removed so it surfaces the real error on retry."""

        method = unregistered_method

        def factory() -> type:
            raise ImportError("optional dependency missing")

        registry.register_encryption_backend_lazy(method, factory)

        with pytest.raises(ImportError, match="optional dependency missing"):
            registry.get_encryption_backend(method)

        assert method in registry.encryption_factories
        assert method not in registry.encryption_backends


class TestGetBlindIndexBackend:
    """Test ``get_blind_index_backend`` resolution."""

    def test_returns_registered_backend(self):
        """Test that a registered blind index backend is returned."""

        assert registry.get_blind_index_backend(BlindIndexMethod.HMAC_SHA256) is HMACSHA256Adapter

    def test_unknown_method_raises_value_error(self, unregistered_blind_index_method: BlindIndexMethod):
        """Test that an unregistered blind index method raises a ValueError."""

        method = unregistered_blind_index_method

        with pytest.raises(ValueError, match="No blind index backend registered"):
            registry.get_blind_index_backend(method)


class TestLoadAwsAdapter:
    """Test the lazily registered AWS adapter factory."""

    def test_load_aws_adapter_imports_adapter(self, unregistered_method: EncryptionMethod):
        """Test that the AWS factory imports and returns the AWSAdapter class."""

        from pydantic_encryption.adapters.encryption.aws import AWSAdapter

        assert registry.load_aws_adapter() is AWSAdapter
