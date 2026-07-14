from enum import StrEnum

from pydantic import BaseModel, ConfigDict

__all__ = ["Provider", "ProviderSettings"]


class Provider(StrEnum):
    """Identify an agent provider supported by the sync system."""

    CLAUDE = "claude"
    CODEX = "codex"
    CURSOR = "cursor"


class ProviderSettings(BaseModel):
    """Validate settings shared by provider output generators."""

    model_config = ConfigDict(extra="allow", strict=True)

    model: str | None = None
