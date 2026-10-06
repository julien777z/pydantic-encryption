import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import FakeSyncKMSClient


class TestAWSAdapterKeyScoping:
    """Test which key each half of the round trip is scoped to."""

    def test_encrypt_refuses_a_decrypt_only_configuration(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a decrypt-only key alone refuses to seal rather than sealing under nothing."""

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        with pytest.raises(ValueError, match="decrypt-only"):
            AWSAdapter.encrypt(b"payload", associated_data=KMS_TEST_CONTEXT)

    def test_unscoped_decrypt_names_no_key(
        self, fake_sync_kms: FakeSyncKMSClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that an unscoped decrypt names no key, letting KMS read it from the wrapped blob."""

        sealed = AWSAdapter.encrypt("payload", associated_data=KMS_TEST_CONTEXT)
        for attr in ("AWS_KMS_KEY_ARN", "AWS_KMS_ENCRYPT_KEY_ARN", "AWS_KMS_DECRYPT_KEY_ARN"):
            monkeypatch.setattr(settings, attr, None)
        AWSAdapter.reset_cache()

        assert AWSAdapter.decrypt(sealed, associated_data=KMS_TEST_CONTEXT) == "payload"
        assert "KeyId" not in fake_sync_kms.decrypt_calls[-1]
