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
