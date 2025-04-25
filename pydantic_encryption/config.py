from typing import Any
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Settings for the package."""

    # Evervault settings
    EVERVAULT_API_KEY: str | None = None
    EVERVAULT_APP_ID: str | None = None
    EVERVAULT_ENCRYPTION_ROLE: str | None = None

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
