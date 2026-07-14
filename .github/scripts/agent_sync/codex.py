import json
import tomllib

from agent_sync.exceptions import AgentSyncConfigError
from agent_sync.markdown import ensure_trailing_newline
from agent_sync.models.providers.codex import CodexSettings

__all__ = ["generate_codex_config"]


def generate_codex_config(settings: CodexSettings) -> str:
    """Render Codex configuration entirely from canonical settings."""

    rendered = ensure_trailing_newline(render_codex_settings_block(settings))

    try:
        tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise AgentSyncConfigError(f"Generated .codex/config.toml is invalid TOML: {exc}") from exc

    return rendered


def render_codex_settings_block(settings: CodexSettings) -> str:
    """Render canonical Codex settings as a marked TOML block."""

    lines = ["# >>> agent-sync managed Codex settings >>>"]
    lines.extend(
        (
            f"approval_policy = {json.dumps(settings.approval_policy, ensure_ascii=False)}",
            f"sandbox_mode = {json.dumps(settings.sandbox_mode, ensure_ascii=False)}",
        )
    )

    if settings.model is not None:
        lines.append(f"model = {json.dumps(settings.model, ensure_ascii=False)}")

    lines.extend(
        (
            f"project_doc_max_bytes = {settings.project_doc_max_bytes}",
            "# <<< agent-sync managed Codex settings <<<",
        )
    )

    return "\n".join(lines)
