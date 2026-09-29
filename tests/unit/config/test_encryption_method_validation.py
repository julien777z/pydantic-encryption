import pytest
from pydantic import ValidationError

from pydantic_encryption.config import Settings
from pydantic_encryption.types import EncryptionMethod


@pytest.mark.usefixtures("isolated_settings_environment")
class TestEncryptionMethodValidation:
    """Test that each encryption method requires the settings it runs on."""

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
