import pytest

from pydantic_encryption.adapters import registry
from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.types import EncryptionMethod


class TestGetEncryptionBackend:
    """Test ``get_encryption_backend`` resolution and lazy loading."""

    @pytest.fixture(autouse=True)
    def empty_registry(self, monkeypatch: pytest.MonkeyPatch):
        """Give each test a registry holding no backends or factories."""

        monkeypatch.setattr(registry, "encryption_backends", {})
        monkeypatch.setattr(registry, "encryption_factories", {})

    def test_registered_backend_returned(self):
        """Test that an eagerly registered backend is returned."""

        registry.register_encryption_backend(EncryptionMethod.FERNET, FernetAdapter)

        assert registry.get_encryption_backend(EncryptionMethod.FERNET) is FernetAdapter

    def test_lazy_factory_invoked_once(self):
        """Test that a lazy factory runs on first use, is cached, and leaves the factories."""

        calls: list[EncryptionMethod] = []

        def factory() -> type[EncryptionAdapter]:
            """Record the call and return the backend."""

            calls.append(EncryptionMethod.AWS)

            return FernetAdapter

        registry.register_encryption_backend_lazy(EncryptionMethod.AWS, factory)

        assert EncryptionMethod.AWS not in registry.encryption_backends
        assert registry.get_encryption_backend(EncryptionMethod.AWS) is FernetAdapter
        assert registry.get_encryption_backend(EncryptionMethod.AWS) is FernetAdapter
        assert registry.encryption_backends[EncryptionMethod.AWS] is FernetAdapter
        assert EncryptionMethod.AWS not in registry.encryption_factories
        assert calls == [EncryptionMethod.AWS]

    def test_backend_cached_under_lock_skips_factory(self, monkeypatch: pytest.MonkeyPatch):
        """Test that a backend cached while waiting for the lock is returned without running the factory."""

        def factory() -> type[EncryptionAdapter]:
            """Fail if run, since the backend is already cached."""

            raise AssertionError("factory must not run once the backend is cached")

        class PopulateOnLock:
            """Lock stand-in that caches the backend as another thread would before entry."""

            def __enter__(self) -> None:
                """Cache the backend on entry."""

                registry.encryption_backends[EncryptionMethod.AWS] = FernetAdapter

            def __exit__(self, *exc_info: object) -> None:
                """Release nothing."""

        registry.register_encryption_backend_lazy(EncryptionMethod.AWS, factory)
        monkeypatch.setattr(registry, "registry_lock", PopulateOnLock())

        assert registry.get_encryption_backend(EncryptionMethod.AWS) is FernetAdapter

    def test_unregistered_method_refused(self):
        """Test that a method with no backend or factory raises."""

        with pytest.raises(ValueError, match="No encryption backend registered"):
            registry.get_encryption_backend(EncryptionMethod.FERNET)

    def test_failing_factory_stays_retryable(self):
        """Test that a failing factory stays registered so a retry surfaces the real error."""

        def factory() -> type[EncryptionAdapter]:
            """Fail as a missing optional dependency would."""

            raise ImportError("optional dependency missing")

        registry.register_encryption_backend_lazy(EncryptionMethod.AWS, factory)

        with pytest.raises(ImportError, match="optional dependency missing"):
            registry.get_encryption_backend(EncryptionMethod.AWS)

        assert EncryptionMethod.AWS in registry.encryption_factories
        assert EncryptionMethod.AWS not in registry.encryption_backends
