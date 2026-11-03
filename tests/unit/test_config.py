import threading

import pytest
from pydantic import ValidationError

from pydantic_encryption.config import Settings
from pydantic_encryption.types import EncryptionMethod


@pytest.mark.usefixtures("isolated_settings_environment")
class TestSettings:
    """Test which settings combinations are accepted, and the reason each refused one gives."""

    @pytest.mark.parametrize(
        ("global_key", "encrypt_key", "decrypt_key"),
        [
            ("arn:aws:kms:us-east-1:000:key/global", None, None),
            (None, "arn:aws:kms:us-east-1:000:key/encrypt", "arn:aws:kms:us-east-1:000:key/decrypt"),
            (None, None, "arn:aws:kms:us-east-1:000:key/decrypt"),
            (None, None, None),
        ],
        ids=["global-only", "separate-pair", "decrypt-only", "none"],
    )
    def test_valid_key_combination(
        self, global_key: str | None, encrypt_key: str | None, decrypt_key: str | None
    ):
        """Test that an accepted combination of key ARNs is kept as given."""

        settings = Settings(
            AWS_KMS_KEY_ARN=global_key,
            AWS_KMS_ENCRYPT_KEY_ARN=encrypt_key,
            AWS_KMS_DECRYPT_KEY_ARN=decrypt_key,
            AWS_KMS_REGION="us-east-1",
        )

        assert (
            settings.AWS_KMS_KEY_ARN,
            settings.AWS_KMS_ENCRYPT_KEY_ARN,
            settings.AWS_KMS_DECRYPT_KEY_ARN,
        ) == (
            global_key,
            encrypt_key,
            decrypt_key,
        )

    @pytest.mark.parametrize(
        ("global_key", "encrypt_key", "decrypt_key", "message"),
        [
            (
                None,
                "arn:aws:kms:us-east-1:000:key/encrypt",
                None,
                "AWS_KMS_ENCRYPT_KEY_ARN requires AWS_KMS_DECRYPT_KEY_ARN",
            ),
            (
                "arn:aws:kms:us-east-1:000:key/global",
                "arn:aws:kms:us-east-1:000:key/encrypt",
                None,
                "Cannot specify AWS_KMS_KEY_ARN together with",
            ),
            (
                "arn:aws:kms:us-east-1:000:key/global",
                None,
                "arn:aws:kms:us-east-1:000:key/decrypt",
                "Cannot specify AWS_KMS_KEY_ARN together with",
            ),
            (
                "arn:aws:kms:us-east-1:000:key/global",
                "arn:aws:kms:us-east-1:000:key/encrypt",
                "arn:aws:kms:us-east-1:000:key/decrypt",
                "Cannot specify AWS_KMS_KEY_ARN together with",
            ),
        ],
        ids=["encrypt-only", "global-with-encrypt", "global-with-decrypt", "all-three"],
    )
    def test_invalid_key_combination(
        self, global_key: str | None, encrypt_key: str | None, decrypt_key: str | None, message: str
    ):
        """Test that a contradictory combination of key ARNs is refused with its reason."""

        with pytest.raises(ValidationError, match=message):
            Settings(
                AWS_KMS_KEY_ARN=global_key,
                AWS_KMS_ENCRYPT_KEY_ARN=encrypt_key,
                AWS_KMS_DECRYPT_KEY_ARN=decrypt_key,
                AWS_KMS_REGION="us-east-1",
            )

    def test_aws_without_credentials_refused(self):
        """Test that the AWS method without region and credentials is refused."""

        with pytest.raises(ValidationError, match="AWS KMS requires"):
            Settings(
                ENCRYPTION_METHOD=EncryptionMethod.AWS, AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:000:key/test"
            )

    def test_aws_with_credentials_accepted(self):
        """Test that the AWS method with a key, region and credentials is accepted."""

        settings = Settings(
            ENCRYPTION_METHOD=EncryptionMethod.AWS,
            AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:000:key/test",
            AWS_KMS_REGION="us-east-1",
            AWS_KMS_ACCESS_KEY_ID="test-access",
            AWS_KMS_SECRET_ACCESS_KEY="test-secret",
        )

        assert settings.ENCRYPTION_METHOD is EncryptionMethod.AWS

    def test_fernet_without_key_refused(self):
        """Test that the Fernet method without an encryption key is refused."""

        with pytest.raises(ValidationError, match="ENCRYPTION_KEY"):
            Settings(ENCRYPTION_METHOD=EncryptionMethod.FERNET)

    def test_fernet_with_key_accepted(self):
        """Test that the Fernet method with an encryption key is accepted."""

        settings = Settings(ENCRYPTION_METHOD=EncryptionMethod.FERNET, ENCRYPTION_KEY="test-key")

        assert settings.ENCRYPTION_METHOD is EncryptionMethod.FERNET

    @pytest.mark.parametrize(
        "setting", ["AWS_KMS_DATA_KEY_MAX_AGE_SECONDS", "AWS_KMS_UNWRAPPED_KEY_MAX_AGE_SECONDS"]
    )
    def test_key_lifetime_past_timer_limit_refused(self, setting: str):
        """Test that a key lifetime longer than a timer can wait is refused rather than stopping expiry."""

        with pytest.raises(ValidationError, match=setting):
            Settings.model_validate({setting: threading.TIMEOUT_MAX * 2})
