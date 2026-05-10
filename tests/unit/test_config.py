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


class TestEncryptionMethodValidation:
    """Test that the validator gates encryption-method-specific env requirements."""

    def test_aws_method_requires_full_aws_settings(self):
        """Test that selecting ENCRYPTION_METHOD=aws without creds raises a validation error."""

        with pytest.raises(ValidationError) as exc_info:
            Settings(
                _env_file=None,
                ENCRYPTION_METHOD="aws",
                AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/test",
            )

        assert "AWS KMS requires" in str(exc_info.value)

    def test_aws_method_with_full_aws_settings_valid(self):
        """Test that ENCRYPTION_METHOD=aws with all required env values constructs cleanly."""

        settings = Settings(
            _env_file=None,
            ENCRYPTION_METHOD="aws",
            AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/test",
            AWS_KMS_REGION="us-east-1",
            AWS_KMS_ACCESS_KEY_ID="test-access",
            AWS_KMS_SECRET_ACCESS_KEY="test-secret",
        )

        assert settings.ENCRYPTION_METHOD.value == "aws"

    def test_fernet_method_with_encryption_key_valid(self):
        """Test that ENCRYPTION_METHOD=fernet with ENCRYPTION_KEY constructs cleanly."""

        settings = Settings(
            _env_file=None,
            ENCRYPTION_METHOD="fernet",
            ENCRYPTION_KEY="test-key",
        )

        assert settings.ENCRYPTION_METHOD.value == "fernet"
