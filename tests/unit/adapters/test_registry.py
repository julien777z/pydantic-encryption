import os

import pytest

from pydantic_encryption.adapters import registry
from pydantic_encryption.adapters.base import EncryptionAdapter
from pydantic_encryption.adapters.blind_index.hmac_sha256 import HMACSHA256Adapter
from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.types import BlindIndexMethod, EncryptionMethod


class TestRegistry:
    """Test how the registry resolves the adapter serving each encryption and blind index method."""

    def test_registered_backend_returned(self, empty_registry: None):
        """Test that an eagerly registered backend is returned."""

        registry.register_encryption_backend(EncryptionMethod.FERNET, FernetAdapter)

        assert registry.get_encryption_backend(EncryptionMethod.FERNET) is FernetAdapter

    def test_lazy_factory_invoked_once(self, empty_registry: None):
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
        assert EncryptionMethod.AWS not in registry.encryption_factories
        assert calls == [EncryptionMethod.AWS]

    def test_backend_cached_under_lock_skips_factory(
        self, empty_registry: None, monkeypatch: pytest.MonkeyPatch
    ):
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

    def test_unregistered_method_refused(self, empty_registry: None):
        """Test that a method with no backend or factory raises."""

        with pytest.raises(ValueError, match="No encryption backend registered"):
            registry.get_encryption_backend(EncryptionMethod.FERNET)

    def test_failing_factory_stays_retryable(self, empty_registry: None):
        """Test that a failing factory stays registered so a retry surfaces the real error."""

        def factory() -> type[EncryptionAdapter]:
            """Fail as a missing optional dependency would."""

            raise ImportError("optional dependency missing")

        registry.register_encryption_backend_lazy(EncryptionMethod.AWS, factory)

        with pytest.raises(ImportError, match="optional dependency missing"):
            registry.get_encryption_backend(EncryptionMethod.AWS)

        assert EncryptionMethod.AWS in registry.encryption_factories
        assert EncryptionMethod.AWS not in registry.encryption_backends

    def test_configured_backend_follows_setting(self):
        """Test that the configured backend is the one ENCRYPTION_METHOD names."""

        assert registry.configured_encryption_backend() is FernetAdapter

    def test_unset_method_refused(self, monkeypatch: pytest.MonkeyPatch):
        """Test that resolving the configured backend raises when ENCRYPTION_METHOD is unset."""

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            registry.configured_encryption_backend()

    def test_aws_factory_imports_adapter(self):
        """Test that the AWS factory imports and returns the AWS adapter class."""

        aws = pytest.importorskip("pydantic_encryption.adapters.encryption.aws")

        assert registry.load_aws_adapter() is aws.AWSAdapter

    def test_registered_blind_index_backend_returned(self):
        """Test that a registered blind index backend is returned."""

        assert registry.get_blind_index_backend(BlindIndexMethod.HMAC_SHA256) is HMACSHA256Adapter

    def test_unregistered_blind_index_method_refused(self, monkeypatch: pytest.MonkeyPatch):
        """Test that a blind index method with no registered backend raises."""

        monkeypatch.setattr(registry, "blind_index_backends", {})

        with pytest.raises(ValueError, match="No blind index backend registered"):
            registry.get_blind_index_backend(BlindIndexMethod.HMAC_SHA256)

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="The platform cannot fork.")
    def test_forked_child_gets_free_lock(self):
        """Test that a child forked while the registry lock is held can still load a backend."""

        with registry.registry_lock:
            child = os.fork()

            if child == 0:
                os._exit(0 if registry.registry_lock.acquire(blocking=False) else 1)

        _, status = os.waitpid(child, 0)

        assert os.waitstatus_to_exitcode(status) == 0
