import secrets
import time
from concurrent.futures import Future
from contextvars import ContextVar
from threading import Condition, Event, Lock
from typing import ClassVar, Final, TypeVar, Unpack

from botocore.config import Config
from botocore.exceptions import ClientError
from pydantic import BaseModel, ConfigDict, Field

from pydantic_encryption.models.kms import (
    DataKeyDecryptRequest,
    DataKeyGenerateRequest,
    DecryptedDataKey,
    GeneratedDataKey,
)

KMS_KEY_ARN: Final[str] = "arn:aws:kms:us-east-1:000000000000:key/sample-key"
KMS_DECRYPT_KEY_ARN: Final[str] = "arn:aws:kms:us-east-1:000000000000:key/sample-decrypt-key"
KMS_REGION: Final[str] = "us-east-1"

ResultT = TypeVar("ResultT")


class FakeSyncKMSClient(BaseModel):
    """Stand-in for the sync boto3 KMS client; mints a distinct data key per call and records calls."""

    plaintext_keys: dict[bytes, bytes] = Field(default_factory=dict)
    generate_calls: list[dict[str, str]] = Field(default_factory=list)
    decrypt_calls: list[dict[str, str | bytes]] = Field(default_factory=list)

    def generate_data_key(self, **kwargs: Unpack[DataKeyGenerateRequest]) -> GeneratedDataKey:
        """Return a fresh plaintext key wrapped under an identifier this fake can recover it by."""

        self.generate_calls.append(dict(kwargs))

        plaintext = secrets.token_bytes(32)
        wrapped = f"wrapped-{len(self.plaintext_keys) + 1}".encode()

        self.plaintext_keys[wrapped] = plaintext

        return GeneratedDataKey(Plaintext=plaintext, CiphertextBlob=wrapped)

    def decrypt(self, **kwargs: Unpack[DataKeyDecryptRequest]) -> DecryptedDataKey:
        """Return the plaintext key the wrapped identifier stands for."""

        self.decrypt_calls.append(dict(kwargs))

        return DecryptedDataKey(Plaintext=self.plaintext_keys[kwargs["CiphertextBlob"]])


class SlowFakeKMS(FakeSyncKMSClient):
    """Fake KMS whose calls take long enough for racing threads to pile up behind one."""

    def generate_data_key(self, **kwargs: Unpack[DataKeyGenerateRequest]) -> GeneratedDataKey:
        """Mint a data key after a delay long enough for racing callers to queue."""

        time.sleep(0.05)

        return super().generate_data_key(**kwargs)

    def decrypt(self, **kwargs: Unpack[DataKeyDecryptRequest]) -> DecryptedDataKey:
        """Unwrap a data key after a delay long enough for racing callers to queue."""

        time.sleep(0.05)

        return super().decrypt(**kwargs)


class ControlledKMSClient(FakeSyncKMSClient):
    """Hold native KMS replies until the test releases them, observing concurrent requests."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    condition: Condition = Field(default_factory=Condition)
    release: Event = Field(default_factory=Event)
    hold_generation: bool = False
    calls: int = 0
    waiters: int = 0
    admission_waiters: int = 0
    error: ClientError | None = None
    invocation_context: ContextVar[bytes] = Field(
        default_factory=lambda: ContextVar("kms_invocation", default=b"")
    )
    observed_contexts: list[bytes] = Field(default_factory=list)

    def held_reply(self) -> None:
        """Count one KMS request, then wait for the test to release it and raise any planned error."""

        with self.condition:
            self.calls += 1
            self.observed_contexts.append(self.invocation_context.get())
            self.condition.notify_all()

        if not self.release.wait(timeout=10):
            raise TimeoutError("The test did not release the KMS request.")

        if self.error is not None:
            raise self.error

    def generate_data_key(self, **kwargs: Unpack[DataKeyGenerateRequest]) -> GeneratedDataKey:
        """Mint a data key, holding the reply only when the test controls generation."""

        if self.hold_generation:
            self.held_reply()

        return super().generate_data_key(**kwargs)

    def decrypt(self, **kwargs: Unpack[DataKeyDecryptRequest]) -> DecryptedDataKey:
        """Hold a native KMS unwrap until the test releases it."""

        self.held_reply()

        return super().decrypt(**kwargs)

    def wait_for_calls(self, count: int) -> bool:
        """Wait for the required KMS requests to overlap."""

        with self.condition:
            return self.condition.wait_for(lambda: self.calls >= count, timeout=5)

    def wait_for_waiters(self, count: int) -> bool:
        """Wait for callers to join one in-flight reply."""

        with self.condition:
            return self.condition.wait_for(lambda: self.waiters >= count, timeout=5)

    def wait_for_admission_waiter(self) -> bool:
        """Wait for a distinct key to encounter the concurrency limit."""

        with self.condition:
            return self.condition.wait_for(lambda: self.admission_waiters > 0, timeout=5)


class ObservedFuture(Future[ResultT]):
    """Native future that reports each caller joining it to the controlled KMS client."""

    control: ClassVar[ControlledKMSClient | None] = None

    def result(self, timeout: float | None = None) -> ResultT:
        """Record a joining caller, then wait on the native future."""

        if self.control is not None:
            with self.control.condition:
                self.control.waiters += 1
                self.control.condition.notify_all()

        return super().result(timeout)


class ObservedCondition(Condition):
    """Native condition that reports each wait for unwrap capacity to the controlled KMS client."""

    def __init__(self, control: ControlledKMSClient) -> None:
        super().__init__()
        self.control = control

    def wait(self, timeout: float | None = None) -> bool:
        """Record a capacity waiter, then wait on the native condition."""

        with self.control.condition:
            self.control.admission_waiters += 1
            self.control.condition.notify_all()

        return super().wait(timeout)


class KMSClientFactory(BaseModel):
    """Capture native SDK client construction while returning the canonical KMS fake."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    calls: list[tuple[str, Config, dict[str, str]]] = Field(default_factory=list)
    condition: Condition = Field(default_factory=Condition)
    release: Event = Field(default_factory=Event)
    hold_creation: bool = False
    client_requests: int = 0

    def __call__(self, service: str, *, config: Config, **kwargs: str) -> FakeSyncKMSClient:
        """Record the configured SDK client request."""

        with self.condition:
            self.calls.append((service, config, kwargs))
            self.condition.notify_all()

        if self.hold_creation and not self.release.wait(timeout=10):
            raise TimeoutError("The test did not release KMS client construction.")

        return FakeSyncKMSClient()

    def wait_for_client_requests(self, count: int) -> bool:
        """Wait until concurrent callers attempt the real initialization lock."""

        with self.condition:
            return self.condition.wait_for(lambda: self.client_requests >= count, timeout=5)


class ObservedLock:
    """Native mutex that reports each contender to the client factory before acquiring it."""

    def __init__(self, factory: KMSClientFactory) -> None:
        self.factory = factory
        self.lock = Lock()

    def __enter__(self) -> None:
        """Record an initialization contender, then acquire the native mutex."""

        with self.factory.condition:
            self.factory.client_requests += 1
            self.factory.condition.notify_all()

        self.lock.acquire()

    def __exit__(self, *_exc: object) -> None:
        """Release the native mutex."""

        self.lock.release()
