from typing import Literal

from pydantic import ConfigDict, Field

from agent_sync.models.providers.providers import ProviderSettings

__all__ = ["CodexSettings"]


class CodexSettings(ProviderSettings):
    """Validate canonical Codex project settings."""

    model_config = ConfigDict(extra="forbid", strict=True)

    approval_policy: Literal["untrusted", "on-request", "never"] = "never"
    sandbox_mode: Literal["read-only", "workspace-write", "danger-full-access"] = (
        "danger-full-access"
    )
    project_doc_max_bytes: int = Field(gt=0)
