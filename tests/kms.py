from typing import Final

import pytest

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings

KMS_TEST_CONTEXT: Final[bytes] = b"tests.kms.payload"
KMS_FOREIGN_CONTEXT: Final[bytes] = b"tests.kms.other_payload"


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
