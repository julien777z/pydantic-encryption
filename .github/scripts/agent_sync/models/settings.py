from pydantic import BaseModel, ConfigDict

from agent_sync.models.providers.claude import ClaudeSettings
from agent_sync.models.providers.codex import CodexSettings
from agent_sync.models.providers.cursor import CursorSettings
from agent_sync.models.providers.providers import Provider, ProviderSettings

__all__ = ["AgentModelOverride", "AgentSyncSettings"]


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
