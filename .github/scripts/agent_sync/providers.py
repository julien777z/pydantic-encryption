import json

from agent_sync.markdown import (
    ensure_trailing_newline,
    has_front_matter,
    normalize_text,
    parse_markdown_file,
    render_front_matter,
    validate_slug,
)
from agent_sync.models.frontmatter import AgentFrontMatter, CommandFrontMatter
from agent_sync.models.outputs import OutputFile, OutputKind
from agent_sync.models.providers.providers import Provider
from agent_sync.models.settings import AgentModelOverride, AgentSyncSettings
from agent_sync.models.workspace import Workspace
from agent_sync.storage import read_text

__all__ = [
    "generate_agent_outputs",
    "generate_command_outputs",
    "generate_hook_outputs",
    "generate_settings_outputs",
]


def generate_command_outputs(workspace: Workspace) -> list[OutputFile]:
    """Generate Claude and Cursor command files."""

    commands_dir = workspace.agents / "commands"

    if not commands_dir.exists():
        return []

    outputs: list[OutputFile] = []
    for path in sorted(commands_dir.glob("*.md")):
        slug = validate_slug(path.stem, path)
        front_matter, content = parse_markdown_file(path, CommandFrontMatter)
        variants = front_matter.variants or {}
        claude_body = normalize_text(variants.get(Provider.CLAUDE, content) or content)
        cursor_body = normalize_text(variants.get(Provider.CURSOR, content) or content)
        excluded_fields = {"variants"}
        claude_content = (
            render_front_matter(
                front_matter,
                claude_body,
                exclude=excluded_fields,
            )
            if has_front_matter(front_matter, exclude=excluded_fields)
            else ensure_trailing_newline(claude_body)
        )
        outputs.extend(
            (
                OutputFile(
                    target_path=workspace.root / ".claude" / "commands" / f"{slug}.md",
                    content=claude_content,
                    kind=OutputKind.CLAUDE_COMMAND,
                    slug=slug,
                    source_path=path,
                ),
                OutputFile(
                    target_path=workspace.root / ".cursor" / "commands" / f"{slug}.md",
                    content=ensure_trailing_newline(cursor_body),
                    kind=OutputKind.CURSOR_COMMAND,
                    slug=slug,
                    source_path=path,
                ),
            )
        )

    return outputs


def generate_agent_outputs(
    workspace: Workspace,
    settings: AgentSyncSettings,
    model_overrides: dict[str, AgentModelOverride],
) -> list[OutputFile]:
    """Generate Claude and Cursor agent files with resolved models."""

    agents_dir = workspace.agents / "agents"

    if not agents_dir.exists():
        return []

    outputs: list[OutputFile] = []
    for path in sorted(agents_dir.glob("*.md")):
        slug = validate_slug(path.stem, path)
        source_front_matter, content = parse_markdown_file(path, AgentFrontMatter)
        for provider in (Provider.CLAUDE, Provider.CURSOR):
            front_matter = source_front_matter.model_copy(deep=True)
            front_matter.model = resolve_agent_model(slug, provider, settings, model_overrides)
            outputs.append(
                OutputFile(
                    target_path=(workspace.root / f".{provider.value}" / "agents" / f"{slug}.md"),
                    content=render_front_matter(front_matter, content),
                    kind=agent_output_kind(provider),
                    slug=slug,
                    source_path=path,
                )
            )

    return outputs


def generate_hook_outputs(workspace: Workspace) -> list[OutputFile]:
    """Generate Claude and Cursor hook files."""

    hooks_dir = workspace.agents / "hooks"

    if not hooks_dir.exists():
        return []

    outputs: list[OutputFile] = []
    for path in sorted(candidate for candidate in hooks_dir.iterdir() if candidate.is_file()):
        content = read_text(path)

        if content is None:
            continue
        for provider in (Provider.CLAUDE, Provider.CURSOR):
            outputs.append(
                OutputFile(
                    target_path=workspace.root / f".{provider.value}" / "hooks" / path.name,
                    content=ensure_trailing_newline(content),
                    kind=hook_output_kind(provider),
                    slug=path.stem,
                    source_path=path,
                )
            )

    return outputs


def generate_settings_outputs(
    workspace: Workspace,
    settings: AgentSyncSettings,
) -> list[OutputFile]:
    """Generate provider settings files from typed canonical settings."""

    if settings.claude is None:
        return []

    content = json.dumps(
        settings.claude.model_dump(exclude_none=True, by_alias=True),
        indent=2,
    )

    return [
        OutputFile(
            target_path=workspace.root / ".claude" / "settings.json",
            content=ensure_trailing_newline(content),
            kind=OutputKind.CLAUDE_SETTINGS,
            slug=Provider.CLAUDE.value,
            source_path=workspace.settings / "claude.json",
        )
    ]


def resolve_agent_model(
    agent_slug: str,
    provider: Provider,
    settings: AgentSyncSettings,
    model_overrides: dict[str, AgentModelOverride],
) -> str | None:
    """Resolve an agent-specific model before its provider default."""

    override = model_overrides.get(agent_slug)
    provider_settings = settings.for_provider(provider)

    return (override.for_provider(provider) if override is not None else None) or (
        provider_settings.model if provider_settings is not None else None
    )


def agent_output_kind(provider: Provider) -> OutputKind:
    """Return the agent output kind for one provider."""

    match provider:
        case Provider.CLAUDE:
            return OutputKind.CLAUDE_AGENT
        case Provider.CURSOR:
            return OutputKind.CURSOR_AGENT
        case Provider.CODEX:
            raise ValueError("Codex does not support generated agent files")


def hook_output_kind(provider: Provider) -> OutputKind:
    """Return the hook output kind for one provider."""

    match provider:
        case Provider.CLAUDE:
            return OutputKind.CLAUDE_HOOK
        case Provider.CURSOR:
            return OutputKind.CURSOR_HOOK
        case Provider.CODEX:
            raise ValueError("Codex does not support generated hook files")
