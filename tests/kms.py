import secrets
from typing import Any

import pytest

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings


class FakeSyncKMSClient:
    """Stand-in for the sync boto3 KMS client; mints a distinct data key per call and records calls."""

    def __init__(self) -> None:
        self.plaintext_keys: dict[bytes, bytes] = {}
        self.generate_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []

    def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        """Return a fresh plaintext key wrapped under an identifier this fake can recover it by."""

        self.generate_calls.append(kwargs)
        plaintext = secrets.token_bytes(32)
        wrapped = f"wrapped-{len(self.plaintext_keys) + 1}".encode("utf-8")
        self.plaintext_keys[wrapped] = plaintext

        return {"Plaintext": plaintext, "CiphertextBlob": wrapped}

    def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        """Return the plaintext key the wrapped identifier stands for."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_keys[kwargs["CiphertextBlob"]]}


class FakeAsyncKMSClient:
    """Stand-in for the aioboto3 KMS client, answering the sync fake's calls asynchronously."""

    def __init__(self) -> None:
        self.kms = FakeSyncKMSClient()

    @property
    def generate_calls(self) -> list[dict[str, Any]]:
        return self.kms.generate_calls

    @property
    def decrypt_calls(self) -> list[dict[str, Any]]:
        return self.kms.decrypt_calls

    async def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        return self.kms.generate_data_key(**kwargs)

    async def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        return self.kms.decrypt(**kwargs)


def reset_adapter_state() -> None:
    """Clear the lazily built KMS clients and every held data key so each test starts cold."""

    AWSAdapter._sync_client = None
    AWSAdapter._async_client = None
    AWSAdapter._async_client_ctx = None
    AWSAdapter._async_loop = None
    AWSAdapter._async_init_lock = None
    AWSAdapter.reset_cache()


def configure_kms_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the AWS KMS settings a fake client still validates against."""

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret-key")
