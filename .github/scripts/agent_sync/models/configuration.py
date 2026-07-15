from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AgentModelOverride",
    "AgentSyncSettings",
    "ClaudeSettings",
    "CodexSettings",
    "CursorSettings",
    "Provider",
    "ProviderSettings",
    "Workspace",
]


class Provider(StrEnum):
    """Identify an agent provider supported by the sync system."""

    CLAUDE = "claude"
    CODEX = "codex"
    CURSOR = "cursor"


class ProviderSettings(BaseModel):
    """Validate settings shared by provider output generators."""

    model_config = ConfigDict(extra="allow", strict=True)

    model: str | None = None


class ClaudeSettings(ProviderSettings):
    """Validate canonical Claude project settings."""


class CodexSettings(ProviderSettings):
    """Validate canonical Codex project settings."""

    model_config = ConfigDict(extra="forbid", strict=True)

    project_doc_max_bytes: int = Field(gt=0)


class CursorSettings(ProviderSettings):
    """Validate canonical Cursor project settings."""


class AgentSyncSettings(BaseModel):
    """Contain validated settings for every supported provider."""

    model_config = ConfigDict(frozen=True)

    claude: ClaudeSettings | None = None
    codex: CodexSettings | None = None
    cursor: CursorSettings | None = None

    def for_provider(self, provider: Provider) -> ProviderSettings | None:
        """Return settings for one provider."""

        match provider:
            case Provider.CLAUDE:
                return self.claude
            case Provider.CODEX:
                return self.codex
            case Provider.CURSOR:
                return self.cursor


class AgentModelOverride(BaseModel):
    """Validate per-provider model overrides for one canonical agent."""

    model_config = ConfigDict(extra="forbid", strict=True)

    claude: str | None = None
    codex: str | None = None
    cursor: str | None = None

    def for_provider(self, provider: Provider) -> str | None:
        """Return the configured model for one provider."""

        match provider:
            case Provider.CLAUDE:
                return self.claude
            case Provider.CODEX:
                return self.codex
            case Provider.CURSOR:
                return self.cursor


class Workspace(BaseModel):
    """Provide canonical and generated paths for one repository."""

    model_config = ConfigDict(frozen=True)

    root: Path

    @property
    def agents(self) -> Path:
        """Return the canonical agent directory."""

        return self.root / ".agents"

    @property
    def settings(self) -> Path:
        """Return the canonical settings directory."""

        return self.agents / "settings"

    @property
    def models(self) -> Path:
        """Return the canonical agent-model directory."""

        return self.agents / "models"
