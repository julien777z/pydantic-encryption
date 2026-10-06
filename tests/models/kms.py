import secrets
import time
from contextvars import ContextVar
from threading import Condition, Event
from typing import Unpack

from botocore.config import Config
from botocore.exceptions import ClientError
from pydantic import BaseModel, ConfigDict, Field

from pydantic_encryption.models.kms import DataKeyDecryptRequest, DataKeyGenerateRequest, GeneratedDataKey


class FakeSyncKMSClient(BaseModel):
    """Stand-in for the sync boto3 KMS client; mints a distinct data key per call and records calls."""

    plaintext_keys: dict[bytes, bytes] = Field(default_factory=dict)
    generate_calls: list[DataKeyGenerateRequest] = Field(default_factory=list)
    decrypt_calls: list[DataKeyDecryptRequest] = Field(default_factory=list)

    def generate_data_key(self, **kwargs: Unpack[DataKeyGenerateRequest]) -> GeneratedDataKey:
        """Return a fresh plaintext key wrapped under an identifier this fake can recover it by."""

        self.generate_calls.append(kwargs)
        plaintext = secrets.token_bytes(32)
        wrapped = f"wrapped-{len(self.plaintext_keys) + 1}".encode("utf-8")
        self.plaintext_keys[wrapped] = plaintext

        return GeneratedDataKey(Plaintext=plaintext, CiphertextBlob=wrapped)

    def decrypt(self, **kwargs: Unpack[DataKeyDecryptRequest]) -> dict[str, bytes]:
        """Return the plaintext key the wrapped identifier stands for."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_keys[kwargs["CiphertextBlob"]]}


class SlowFakeKMS(FakeSyncKMSClient):
    """Fake KMS whose calls take long enough for racing threads to pile up behind one."""

    def generate_data_key(self, **kwargs: Unpack[DataKeyGenerateRequest]) -> GeneratedDataKey:
        """Mint a data key after a delay long enough for racing callers to queue."""

        time.sleep(0.05)

        return super().generate_data_key(**kwargs)

    def decrypt(self, **kwargs: Unpack[DataKeyDecryptRequest]) -> dict[str, bytes]:
        """Unwrap a data key after a delay long enough for racing callers to queue."""

        time.sleep(0.05)

        return super().decrypt(**kwargs)


class ControlledKMSClient(FakeSyncKMSClient):
    """Control native KMS replies and observe concurrent requests without replacing adapter behavior."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    condition: Condition = Field(default_factory=Condition)
    release: Event = Field(default_factory=Event)
    calls: int = 0
    waiters: int = 0
    admission_waiters: int = 0
    error: ClientError | None = None
    invocation_context: ContextVar[bytes] = Field(
        default_factory=lambda: ContextVar("kms_invocation", default=b"")
    )
    observed_contexts: list[bytes] = Field(default_factory=list)

    def decrypt(self, **kwargs: Unpack[DataKeyDecryptRequest]) -> dict[str, bytes]:
        """Hold a native KMS reply until the test releases it."""

        with self.condition:
            self.calls += 1
            self.observed_contexts.append(self.invocation_context.get())
            self.condition.notify_all()

        if not self.release.wait(timeout=10):
            raise TimeoutError("The test did not release the KMS request.")

        if self.error is not None:
            raise self.error

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
