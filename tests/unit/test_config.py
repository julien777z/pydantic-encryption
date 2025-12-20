import pytest
from pydantic import ValidationError

from pydantic_encryption.config import Settings


class TestAWSKMSKeyValidation:
    """Test AWS KMS key ARN validation rules."""

    def test_global_key_only_valid(self):
        """Test that using only AWS_KMS_KEY_ARN is valid."""

        settings = Settings(
            _env_file=None,
            AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/test-key",
            AWS_KMS_REGION="us-east-1",
        )

        assert settings.AWS_KMS_KEY_ARN == "arn:aws:kms:us-east-1:123456789:key/test-key"
        assert settings.AWS_KMS_ENCRYPT_KEY_ARN is None
        assert settings.AWS_KMS_DECRYPT_KEY_ARN is None

    def test_separate_keys_valid(self):
        """Test that using both separate encrypt and decrypt keys is valid."""

        settings = Settings(
            _env_file=None,
            AWS_KMS_ENCRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/encrypt-key",
            AWS_KMS_DECRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/decrypt-key",
            AWS_KMS_REGION="us-east-1",
        )

        assert settings.AWS_KMS_KEY_ARN is None
        assert settings.AWS_KMS_ENCRYPT_KEY_ARN == "arn:aws:kms:us-east-1:123456789:key/encrypt-key"
        assert settings.AWS_KMS_DECRYPT_KEY_ARN == "arn:aws:kms:us-east-1:123456789:key/decrypt-key"

    def test_decrypt_key_only_valid(self):
        """Test that using only decrypt key is valid (read-only scenario)."""

        settings = Settings(
            _env_file=None,
            AWS_KMS_DECRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/decrypt-key",
            AWS_KMS_REGION="us-east-1",
        )

        assert settings.AWS_KMS_KEY_ARN is None
        assert settings.AWS_KMS_ENCRYPT_KEY_ARN is None
        assert settings.AWS_KMS_DECRYPT_KEY_ARN == "arn:aws:kms:us-east-1:123456789:key/decrypt-key"

    def test_encrypt_key_only_invalid(self):
        """Test that using only encrypt key without decrypt key is invalid."""

        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,
                AWS_KMS_ENCRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/encrypt-key",
                AWS_KMS_REGION="us-east-1",
            )

        assert "AWS_KMS_ENCRYPT_KEY_ARN requires AWS_KMS_DECRYPT_KEY_ARN" in str(exc_info.value)

    def test_global_with_encrypt_key_invalid(self):
        """Test that using global key with encrypt key is invalid."""

        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,
                AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/global-key",
                AWS_KMS_ENCRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/encrypt-key",
                AWS_KMS_REGION="us-east-1",
            )
        assert "Cannot specify AWS_KMS_KEY_ARN together with" in str(exc_info.value)

    def test_global_with_decrypt_key_invalid(self):
        """Test that using global key with decrypt key is invalid."""

        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,
                AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/global-key",
                AWS_KMS_DECRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/decrypt-key",
                AWS_KMS_REGION="us-east-1",
            )
        assert "Cannot specify AWS_KMS_KEY_ARN together with" in str(exc_info.value)

    def test_all_three_keys_invalid(self):
        """Test that using all three keys is invalid."""

        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,
                AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/global-key",
                AWS_KMS_ENCRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/encrypt-key",
                AWS_KMS_DECRYPT_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/decrypt-key",
                AWS_KMS_REGION="us-east-1",
            )
        assert "Cannot specify AWS_KMS_KEY_ARN together with" in str(exc_info.value)

    def test_no_keys_valid(self):
        """Test that having no AWS keys is valid (might use different encryption method)."""

        settings = Settings(_env_file=None)

        assert settings.AWS_KMS_KEY_ARN is None
        assert settings.AWS_KMS_ENCRYPT_KEY_ARN is None
        assert settings.AWS_KMS_DECRYPT_KEY_ARN is None
