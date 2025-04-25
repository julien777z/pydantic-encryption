from typing import Any, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Settings for the package."""

    # Cryptography settings
    ENCRYPTION_KEY: Optional[str] = None

    # Evervault settings
    EVERVAULT_API_KEY: Optional[str] = None
    EVERVAULT_APP_ID: Optional[str] = None
    EVERVAULT_ENCRYPTION_ROLE: Optional[str] = None

    class Config:
        env_file = [".env.local", ".env"]
        case_sensitive = True
        extra = "ignore"


settings = Settings()
