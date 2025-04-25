from typing import Any, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Settings for the package."""

    # Evervault settings
    EVERVAULT_API_KEY: Optional[str] = None
    EVERVAULT_APP_ID: Optional[str] = None
    EVERVAULT_ENCRYPTION_ROLE: Optional[str] = None

    class Config:
        env_file = [".env.local", ".env"]
        case_sensitive = True
        extra = "ignore"

    def model_post_init(self, context: Any, /) -> None:
        try:
            import evervault  # pylint: disable=unused-import
        except ImportError:
            pass
        else:
            if not (
                self.EVERVAULT_APP_ID
                and self.EVERVAULT_API_KEY
                and self.EVERVAULT_ENCRYPTION_ROLE
            ):
                raise ValueError("Evervault settings are not configured")

        return super().model_post_init(context)


settings = Settings()
