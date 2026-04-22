from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from pydantic_encryption.types import EncryptionMethod


class Settings(BaseSettings):
    """Environment-driven configuration for the package."""

    ENCRYPTION_KEY: str | None = None

    AWS_KMS_KEY_ARN: str | None = None
    AWS_KMS_ENCRYPT_KEY_ARN: str | None = None
    AWS_KMS_DECRYPT_KEY_ARN: str | None = None
    AWS_KMS_REGION: str | None = None
    AWS_KMS_ACCESS_KEY_ID: str | None = None
    AWS_KMS_SECRET_ACCESS_KEY: str | None = None

    BLIND_INDEX_SECRET_KEY: str | None = None

    ENCRYPTION_METHOD: EncryptionMethod | None = None

    AWS_KMS_PLAINTEXT_CACHE_ENABLED: bool = False
    AWS_KMS_PLAINTEXT_CACHE_CAPACITY: int = 2048

    DECRYPT_CONCURRENCY: int = 32

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
