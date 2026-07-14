from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from agent_sync.models.settings import AgentSyncSettings
from agent_sync.models.workspace import Workspace

__all__ = ["ValidationCheck", "ValidationContext"]


class ValidationContext(BaseModel):
    """Provide canonical inputs shared by validation checks."""

    model_config = ConfigDict(frozen=True)

    workspace: Workspace
    settings: AgentSyncSettings


class ValidationCheck(BaseModel):
    """Name and execute one canonical agent-sync validation."""

    model_config = ConfigDict(frozen=True)

    name: str
    run: Callable[[ValidationContext], None]
