from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic_encryption.annotations import EncryptionMethod


class Settings(BaseSettings):
    """Settings for the package."""

    # Fernet settings
    ENCRYPTION_KEY: Optional[str] = None

    # AWS KMS settings
    AWS_KMS_KEY_ARN: Optional[str] = None
    AWS_KMS_REGION: Optional[str] = None
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None

    # Evervault settings
    EVERVAULT_API_KEY: Optional[str] = None
    EVERVAULT_APP_ID: Optional[str] = None
    EVERVAULT_ENCRYPTION_ROLE: Optional[str] = None

    # Encryption settings
    ENCRYPTION_METHOD: EncryptionMethod = EncryptionMethod.FERNET

    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
