import pytest
from pydantic import ValidationError

from pydantic_encryption.config import Settings


@pytest.mark.usefixtures("isolated_settings_environment")
class TestAWSKMSKeyValidation:
    """Test which combinations of AWS KMS key ARNs the settings accept."""

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
    def test_valid_combination(
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
    def test_invalid_combination(
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
