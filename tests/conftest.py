from collections import OrderedDict
from collections.abc import Iterator
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import Settings, settings
from pydantic_encryption.types import EncryptionMethod
from tests.factories import User, UserFactory
from tests.models.kms import (
    KMS_KEY_ARN,
    KMS_REGION,
    ControlledKMSClient,
    FakeSyncKMSClient,
    KMSClientFactory,
    ObservedCondition,
    ObservedFuture,
    ObservedLock,
    SlowFakeKMS,
)


@pytest.fixture(autouse=True)
def set_default_encryption_method(monkeypatch):
    """Set encryption and blind-index config for every test so individual tests can opt out."""

    monkeypatch.setattr(settings, "ENCRYPTION_METHOD", EncryptionMethod.FERNET)

    if settings.ENCRYPTION_KEY is None:
        monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())

    if settings.BLIND_INDEX_SECRET_KEY is None:
        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "test-blind-index-secret-key")


@pytest.fixture
def empty_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give the test a registry holding no encryption backends or factories."""

    monkeypatch.setattr("pydantic_encryption.adapters.registry.encryption_backends", {})
    monkeypatch.setattr("pydantic_encryption.adapters.registry.encryption_factories", {})


@pytest.fixture
def fernet_key() -> str:
    """Generate a Fernet root key for tests that exercise that backend directly."""

    return Fernet.generate_key().decode()


@pytest.fixture
def aws_adapter_state(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Give the AWS adapter no client, no held keys and no calls in flight, with KMS settings set."""

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", KMS_KEY_ARN)
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", KMS_REGION)
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "sample-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "sample-secret-key")

    monkeypatch.setattr(AWSAdapter, "kms_client", None)
    monkeypatch.setattr(AWSAdapter, "encrypt_key", None)
    monkeypatch.setattr(AWSAdapter, "unwrapped_keys", OrderedDict())
    monkeypatch.setattr(AWSAdapter, "expiry_timer", None)
    monkeypatch.setattr(AWSAdapter, "generating", None)
    monkeypatch.setattr(AWSAdapter, "unwrapping", {})

    yield

    with AWSAdapter.cache_lock:
        if AWSAdapter.expiry_timer is not None:
            AWSAdapter.expiry_timer.cancel()


@pytest.fixture
def fake_sync_kms(aws_adapter_state: None, monkeypatch: pytest.MonkeyPatch) -> FakeSyncKMSClient:
    """Install a fake KMS client as the adapter's client."""

    client = FakeSyncKMSClient()

    monkeypatch.setattr(AWSAdapter, "kms_client", client)

    return client


@pytest.fixture
def slow_kms(aws_adapter_state: None, monkeypatch: pytest.MonkeyPatch) -> SlowFakeKMS:
    """Install a fake KMS client slow enough for racing callers to queue behind one call."""

    client = SlowFakeKMS()

    monkeypatch.setattr(AWSAdapter, "kms_client", client)

    return client


@pytest.fixture
def kms_client_factory(aws_adapter_state: None, monkeypatch: pytest.MonkeyPatch) -> KMSClientFactory:
    """Capture the real adapter's SDK client construction."""

    factory = KMSClientFactory()

    monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.boto3.client", factory)

    return factory


@pytest.fixture
def concurrent_kms_client_factory(
    kms_client_factory: KMSClientFactory, monkeypatch: pytest.MonkeyPatch
) -> Iterator[KMSClientFactory]:
    """Hold SDK construction while observing callers at the real initialization lock."""

    kms_client_factory.hold_creation = True

    monkeypatch.setattr(AWSAdapter, "client_lock", ObservedLock(kms_client_factory))

    yield kms_client_factory

    kms_client_factory.release.set()


@pytest.fixture
def controlled_kms(aws_adapter_state: None, monkeypatch: pytest.MonkeyPatch) -> Iterator[ControlledKMSClient]:
    """Install a controllable KMS boundary and observe waits on the adapter's real primitives."""

    control = ControlledKMSClient()

    monkeypatch.setattr(AWSAdapter, "kms_client", control)
    monkeypatch.setattr(AWSAdapter, "unwrapping_condition", ObservedCondition(control))
    monkeypatch.setattr(ObservedFuture, "control", control)
    monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.Future", ObservedFuture)

    yield control

    control.release.set()


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
