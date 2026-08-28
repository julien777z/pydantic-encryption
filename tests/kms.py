from typing import Any

import pytest

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings

DATA_KEY: bytes = b"\x00" * 32


class FakeSyncKMSClient:
    """Stand-in for the sync boto3 KMS client; records calls and returns deterministic blobs."""

    def __init__(self, plaintext_data_key: bytes) -> None:
        self.plaintext_data_key = plaintext_data_key
        self.generate_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.next_wrapped_key: bytes = b"wrapped-key"

    def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        """Return a fixed plaintext key and a unique wrapped key per call."""

        self.generate_calls.append(kwargs)

        return {
            "Plaintext": self.plaintext_data_key,
            "CiphertextBlob": self.next_wrapped_key,
        }

    def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        """Return the fixed plaintext key for any wrapped key."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_data_key}


class FakeAsyncKMSClient:
    """Stand-in for the aioboto3 KMS client; records calls and returns deterministic blobs."""

    def __init__(self, plaintext_data_key: bytes) -> None:
        self.plaintext_data_key = plaintext_data_key
        self.generate_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.next_wrapped_key: bytes = b"wrapped-key"

    async def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        """Return a fixed plaintext key and a unique wrapped key per call."""

        self.generate_calls.append(kwargs)

        return {
            "Plaintext": self.plaintext_data_key,
            "CiphertextBlob": self.next_wrapped_key,
        }

    async def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        """Return the fixed plaintext key for any wrapped key."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_data_key}


def reset_adapter_state() -> None:
    """Clear lazily-initialized KMS clients so each test starts fresh."""

    AWSAdapter._sync_client = None
    AWSAdapter._async_client = None
    AWSAdapter._async_client_ctx = None
    AWSAdapter._async_loop = None
    AWSAdapter._async_init_lock = None


def configure_kms_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed the AWS KMS settings a fake client still validates against."""

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret-key")


class FakeClientCtx:
    """Async context manager standing in for the aioboto3 client context."""

    def __init__(self, client: FakeAsyncKMSClient) -> None:
        self.client = client

    async def __aenter__(self) -> FakeAsyncKMSClient:
        """Return the fake async KMS client."""

        return self.client

    async def __aexit__(self, *exc: Any) -> None:
        """Close the fake context without releasing anything."""


class FakeAioSession:
    """Stand-in for ``aioboto3.Session`` that hands out fake async KMS clients."""

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs

    def client(self, service: str, **client_kwargs: Any) -> FakeClientCtx:
        """Return a context manager yielding a fake async KMS client."""

        return FakeClientCtx(FakeAsyncKMSClient(plaintext_data_key=DATA_KEY))


def install_fake_kms(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed KMS settings and route both boto3 and aioboto3 client construction at the fakes."""

    configure_kms_settings(monkeypatch)

    def fake_boto3_client(service: str, **kwargs: Any) -> FakeSyncKMSClient:
        """Return a fake sync KMS client for any requested service."""

        return FakeSyncKMSClient(plaintext_data_key=DATA_KEY)

    monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.boto3.client", fake_boto3_client)
    monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.aioboto3.Session", FakeAioSession)
