from typing import Self

from pydantic import Field, model_validator
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

    KMS_DATA_KEY_MAX_AGE_SECONDS: int = Field(default=300, gt=0)
    KMS_DATA_KEY_MAX_USES: int = Field(default=1000, gt=0)
    KMS_DATA_KEY_MAX_BYTES: int = Field(default=2**30, gt=0)
    KMS_MATERIALS_CACHE_SIZE: int = Field(default=512, gt=0)
    KMS_CRYPTO_MAX_WORKERS: int = Field(default=64, gt=0)

    BLIND_INDEX_SECRET_KEY: str | None = None

    ENCRYPTION_METHOD: EncryptionMethod | None = None

    @model_validator(mode="after")
    def validate_encryption_settings(self) -> Self:
        """Validate every encryption-related env combination at import time, once."""

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

        if self.ENCRYPTION_METHOD is EncryptionMethod.AWS and not (
            (global_key or encrypt_key or decrypt_key)
            and self.AWS_KMS_REGION
            and self.AWS_KMS_ACCESS_KEY_ID
            and self.AWS_KMS_SECRET_ACCESS_KEY
        ):
            raise ValueError(
                "AWS KMS requires AWS_KMS_REGION, AWS_KMS_ACCESS_KEY_ID, "
                "AWS_KMS_SECRET_ACCESS_KEY, and at least one key ARN "
                "(AWS_KMS_KEY_ARN, AWS_KMS_ENCRYPT_KEY_ARN, or AWS_KMS_DECRYPT_KEY_ARN) to be set."
            )

        if self.ENCRYPTION_METHOD is EncryptionMethod.FERNET and not self.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_METHOD=fernet requires ENCRYPTION_KEY to be set.")

        return self

    model_config = SettingsConfigDict(
        env_file=[".env.local", ".env"],
        case_sensitive=False,
        extra="ignore",
    )


settings = Settings()
