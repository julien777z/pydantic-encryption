from collections.abc import Iterator
from concurrent.futures import Future
from pathlib import Path
from threading import Condition, Lock

import pytest
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import Settings, settings
from pydantic_encryption.types import EncryptionMethod
from tests.factories import User, UserFactory
from tests.kms import configure_kms_settings, reset_adapter_state
from tests.models.kms import ControlledKMSClient, FakeSyncKMSClient, KMSClientFactory


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Set encryption and blind-index config for every test so individual tests can opt out."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    if settings.ENCRYPTION_KEY is None:
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())

    if settings.BLIND_INDEX_SECRET_KEY is None:
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-blind-index-secret-key")


@pytest.fixture
def fernet_key() -> str:
    """Generate a Fernet root key for tests that exercise that backend directly."""

    return Fernet.generate_key().decode()


@pytest.fixture
def fake_sync_kms(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeSyncKMSClient]:
    """Install a fake KMS client and set AWS settings for the test process."""

    reset_adapter_state()

    configure_kms_settings(monkeypatch)

    client = FakeSyncKMSClient()
    monkeypatch.setattr(AWSAdapter, "_sync_client", client)

    yield client

    reset_adapter_state()


@pytest.fixture
def kms_client_factory(monkeypatch: pytest.MonkeyPatch) -> Iterator[KMSClientFactory]:
    """Capture the real adapter's SDK client construction and clean up its lifecycle."""

    reset_adapter_state()
    configure_kms_settings(monkeypatch)
    factory = KMSClientFactory()

    monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.boto3.client", factory)

    yield factory

    reset_adapter_state()


@pytest.fixture
def concurrent_kms_client_factory(
    kms_client_factory: KMSClientFactory, monkeypatch: pytest.MonkeyPatch
) -> Iterator[KMSClientFactory]:
    """Hold SDK construction while observing callers at the real initialization lock."""

    kms_client_factory.hold_creation = True
    lock = Lock()

    class _ObservedLock:
        """Count attempts while preserving native mutex acquisition and release."""

        def __enter__(self) -> None:
            """Observe an initialization contender before acquiring the real mutex."""

            with kms_client_factory.condition:
                kms_client_factory.client_requests += 1
                kms_client_factory.condition.notify_all()

            lock.acquire()

        def __exit__(self, *_exc: object) -> None:
            """Release the mutex using the native lock operation."""

            lock.release()

    monkeypatch.setattr(AWSAdapter, "client_lock", _ObservedLock())

    yield kms_client_factory

    kms_client_factory.release.set()


@pytest.fixture
def controlled_kms(fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch) -> ControlledKMSClient:
    """Install a controllable KMS boundary and measure real synchronization waits."""

    control = ControlledKMSClient()
    monkeypatch.setattr(AWSAdapter, "_sync_client", control)

    class _ObservedFuture(Future[bytes]):
        """Measure a caller waiting on the real shared future."""

        def result(self, timeout: float | None = None) -> bytes:
            """Record a joining caller and delegate to the native future."""

            with control.condition:
                control.waiters += 1
                control.condition.notify_all()

            return super().result(timeout)

    class _ObservedCondition(Condition):
        """Measure actual admission waits without changing condition behavior."""

        def wait(self, timeout: float | None = None) -> bool:
            """Record a capacity waiter and delegate to the native condition."""

            with control.condition:
                control.admission_waiters += 1
                control.condition.notify_all()

            return super().wait(timeout)

    monkeypatch.setattr(AWSAdapter, "unwrapping_condition", _ObservedCondition())
    monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.Future", _ObservedFuture)

    return control


@pytest.fixture
def kms_failure() -> ClientError:
    """Provide a native KMS throttling response."""

    return ClientError(
        {"Error": {"Code": "ThrottlingException", "Message": "Synthetic KMS failure"}}, "Decrypt"
    )


@pytest.fixture
def user() -> User:
    """Generate a User instance with encrypted address and hashed password."""

    return UserFactory.build()


@pytest.fixture
def other_user() -> User:
    """Generate a second User instance distinct from ``user``."""

    return UserFactory.build()


@pytest.fixture
def users_batch() -> list[User]:
    """Generate a batch of User instances."""

    return UserFactory.batch(5)


@pytest.fixture
def isolated_settings_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Run in a directory with no dotenv files and no settings variables in the environment."""

    monkeypatch.chdir(tmp_path)

    for name in Settings.model_fields:
        monkeypatch.delenv(name, raising=False)
