import secrets
import time
from typing import Unpack

import pytest

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.models.kms import DataKeyDecryptRequest, DataKeyGenerateRequest, GeneratedDataKey


class FakeSyncKMSClient:
    """Stand-in for the sync boto3 KMS client; mints a distinct data key per call and records calls."""

    def __init__(self) -> None:
        self.plaintext_keys: dict[bytes, bytes] = {}
        self.generate_calls: list[DataKeyGenerateRequest] = []
        self.decrypt_calls: list[DataKeyDecryptRequest] = []

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


def reset_adapter_state() -> None:
    """Clear the lazily built KMS client and every held data key so each test starts cold."""

    AWSAdapter._sync_client = None
    AWSAdapter.reset_cache()


def configure_kms_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the AWS KMS settings a fake client still validates against."""

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret-key")
