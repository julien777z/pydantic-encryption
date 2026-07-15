import json
import tomllib

from agent_sync.configuration import AgentSyncConfigError
from agent_sync.instructions import (
    assemble_universal_agent_instructions,
    generate_rule_outputs,
    generate_skill_outputs,
)
from agent_sync.markdown import ensure_trailing_newline
from agent_sync.models.configuration import (
    AgentModelOverride,
    AgentSyncSettings,
    CodexSettings,
    Provider,
    Workspace,
)
from agent_sync.models.outputs import OutputFile, OutputKind
from agent_sync.providers import (
    generate_agent_outputs,
    generate_command_outputs,
    generate_hook_outputs,
    generate_settings_outputs,
)

__all__ = ["generate_outputs"]


def generate_outputs(
    workspace: Workspace,
    settings: AgentSyncSettings,
    model_overrides: dict[str, AgentModelOverride],
) -> list[OutputFile]:
    """Generate every provider output from canonical agent sources."""

    return [
        *generate_skill_outputs(workspace),
        *generate_command_outputs(workspace),
        *generate_agent_outputs(workspace, settings, model_overrides),
        *generate_rule_outputs(workspace),
        *generate_universal_agent_instruction_outputs(workspace),
        *generate_codex_settings_outputs(workspace, settings),
        *generate_hook_outputs(workspace),
        *generate_settings_outputs(workspace, settings),
    ]


def generate_universal_agent_instruction_outputs(workspace: Workspace) -> list[OutputFile]:
    """Generate Universal Agent Instructions from canonical rules."""

    rules_dir = workspace.agents / "rules"

    if not rules_dir.exists():
        return []

    return [
        OutputFile(
            target_path=workspace.root / "AGENTS.md",
            content=assemble_universal_agent_instructions(workspace),
            kind=OutputKind.UNIVERSAL_AGENT_INSTRUCTIONS,
            slug="universal-agent-instructions",
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

    agents_content = assemble_universal_agent_instructions(workspace)
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


def generate_codex_config(settings: CodexSettings) -> str:
    """Render Codex configuration entirely from canonical settings."""

    lines = ["# >>> agent-sync managed Codex settings >>>"]

    if settings.model is not None:
        lines.append(f"model = {json.dumps(settings.model, ensure_ascii=False)}")

    lines.extend(
        (
            f"project_doc_max_bytes = {settings.project_doc_max_bytes}",
            "# <<< agent-sync managed Codex settings <<<",
        )
    )
    rendered = ensure_trailing_newline("\n".join(lines))

    try:
        tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise AgentSyncConfigError(f"Generated .codex/config.toml is invalid TOML: {exc}") from exc

    return rendered
