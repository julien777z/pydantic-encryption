import json

from agent_sync.codex import generate_codex_config
from agent_sync.markdown import ensure_trailing_newline
from agent_sync.models.outputs import OutputFile, OutputKind
from agent_sync.models.providers.codex import CodexSettings
from agent_sync.models.providers.providers import Provider
from agent_sync.models.settings import AgentModelOverride, AgentSyncSettings
from agent_sync.models.workspace import Workspace
from agent_sync.providers import (
    generate_agent_outputs,
    generate_command_outputs,
    generate_hook_outputs,
    generate_settings_outputs,
)
from agent_sync.rules import assemble_agents_instructions, generate_rule_outputs
from agent_sync.skills import generate_skill_outputs
from agent_sync.validation import run_validations

__all__ = ["generate_outputs"]


def generate_outputs(
    workspace: Workspace,
    settings: AgentSyncSettings,
    model_overrides: dict[str, AgentModelOverride],
) -> list[OutputFile]:
    """Generate every provider output from canonical agent sources."""

    run_validations(workspace, settings)

    return [
        *generate_skill_outputs(workspace),
        *generate_command_outputs(workspace),
        *generate_agent_outputs(workspace, settings, model_overrides),
        *generate_rule_outputs(workspace),
        *generate_agents_instruction_outputs(workspace),
        *generate_codex_settings_outputs(workspace, settings),
        *generate_hook_outputs(workspace),
        *generate_settings_outputs(workspace, settings),
    ]


def generate_agents_instruction_outputs(workspace: Workspace) -> list[OutputFile]:
    """Generate universal root instructions from canonical rules."""

    rules_dir = workspace.agents / "rules"

    if not rules_dir.exists():
        return []

    return [
        OutputFile(
            target_path=workspace.root / "AGENTS.md",
            content=assemble_agents_instructions(workspace),
            kind=OutputKind.AGENTS_INSTRUCTIONS,
            slug="agents",
            source_path=rules_dir,
        )
    ]


def generate_codex_settings_outputs(
    workspace: Workspace,
    settings: AgentSyncSettings,
) -> list[OutputFile]:
    """Generate canonical and provider Codex settings."""

    if settings.codex is None:
        return []

    agents_content = assemble_agents_instructions(workspace)
    source_path = workspace.settings / "codex.json"
    synchronized_settings = settings.codex.model_copy(
        update={"project_doc_max_bytes": len(agents_content.encode("utf-8"))}
    )
    config_path = workspace.root / ".codex" / "config.toml"
    config_content = generate_codex_config(synchronized_settings)

    outputs = [
        OutputFile(
            target_path=config_path,
            content=config_content,
            kind=OutputKind.CODEX_SETTINGS,
            slug=Provider.CODEX.value,
            source_path=source_path,
        ),
    ]

    if source_path.exists():
        outputs.append(
            OutputFile(
                target_path=source_path,
                content=render_codex_settings(synchronized_settings),
                kind=OutputKind.AGENTS_CODEX_SETTINGS,
                slug=Provider.CODEX.value,
                source_path=source_path,
            )
        )

    return outputs


def render_codex_settings(settings: CodexSettings) -> str:
    """Serialize canonical Codex settings with the synchronized instruction capacity."""

    return ensure_trailing_newline(json.dumps(settings.model_dump(exclude_none=True), indent=2))
