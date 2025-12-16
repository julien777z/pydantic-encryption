from typing import Optional, Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from pydantic_encryption.types import EncryptionMethod


class Settings(BaseSettings):
    """Settings for the package."""

    # Fernet settings
    ENCRYPTION_KEY: Optional[str] = None

    # AWS KMS settings
    AWS_KMS_KEY_ARN: Optional[str] = None
    AWS_KMS_ENCRYPT_KEY_ARN: Optional[str] = None
    AWS_KMS_DECRYPT_KEY_ARN: Optional[str] = None
    AWS_KMS_REGION: Optional[str] = None
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None

    # Evervault settings
    EVERVAULT_API_KEY: Optional[str] = None
    EVERVAULT_APP_ID: Optional[str] = None
    EVERVAULT_ENCRYPTION_ROLE: Optional[str] = None

    # Encryption settings
    ENCRYPTION_METHOD: EncryptionMethod = EncryptionMethod.FERNET

    @model_validator(mode="after")
    def validate_aws_kms_keys(self) -> Self:
        global_key = self.AWS_KMS_KEY_ARN
        encrypt_key = self.AWS_KMS_ENCRYPT_KEY_ARN
        decrypt_key = self.AWS_KMS_DECRYPT_KEY_ARN

        if global_key and (encrypt_key or decrypt_key):
            raise ValueError(
                "Cannot specify AWS_KMS_KEY_ARN together with "
                "AWS_KMS_ENCRYPT_KEY_ARN or AWS_KMS_DECRYPT_KEY_ARN. "
                "Use either the global key or separate encrypt/decrypt keys."
            )

        if encrypt_key and not decrypt_key:
            raise ValueError(
                "AWS_KMS_ENCRYPT_KEY_ARN requires AWS_KMS_DECRYPT_KEY_ARN to be set. "
                "You can specify decrypt key alone for read-only scenarios, "
                "but encrypt key requires a corresponding decrypt key."
            )

        return self

    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
