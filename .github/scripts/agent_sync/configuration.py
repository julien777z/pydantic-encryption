import logging
from pathlib import Path

from pydantic import BaseModel, ValidationError

from agent_sync.markdown import validate_slug
from agent_sync.models.configuration import (
    AgentModelOverride,
    AgentSyncSettings,
    ClaudeSettings,
    CodexSettings,
    CursorSettings,
    Workspace,
)

__all__ = [
    "AgentSyncConfigError",
    "load_agent_model_overrides",
    "load_settings",
]

logger = logging.getLogger(__name__)


class AgentSyncConfigError(ValueError):
    """Report invalid canonical agent configuration."""


def load_settings(workspace: Workspace) -> AgentSyncSettings:
    """Load canonical settings for every supported provider."""

    return AgentSyncSettings(
        claude=load_model(workspace.settings / "claude.json", ClaudeSettings),
        codex=load_model(workspace.settings / "codex.json", CodexSettings, required_valid=True),
        cursor=load_model(workspace.settings / "cursor.json", CursorSettings),
    )


def load_agent_model_overrides(workspace: Workspace) -> dict[str, AgentModelOverride]:
    """Load typed per-agent model overrides by agent slug."""

    if not workspace.models.exists():
        return {}

    overrides: dict[str, AgentModelOverride] = {}
    for path in sorted(workspace.models.glob("*.json")):
        slug = validate_slug(path.stem, path)
        override = load_model(path, AgentModelOverride)

        if override is not None:
            overrides[slug] = override

    return overrides


def load_model[SettingsModel: BaseModel](
    path: Path,
    model: type[SettingsModel],
    *,
    required_valid: bool = False,
) -> SettingsModel | None:
    """Load one JSON-backed model with configurable invalid-data handling."""

    if not path.exists():
        return None

    try:
        return model.model_validate_json(path.read_text(encoding="utf-8"))
    except ValidationError as exc:
        if required_valid:
            raise AgentSyncConfigError(f"Invalid settings in {path}: {exc}") from exc

        logger.warning("Invalid settings in %s: %s", path, exc)

        return None
