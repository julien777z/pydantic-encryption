from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

__all__ = ["DiffEntry", "OutputFile", "OutputKind"]


class OutputKind(StrEnum):
    """Identify a generated output category."""

    AGENTS_RULE = "agents_rule"
    AGENTS_CODEX_SETTINGS = "agents_codex_settings"
    CLAUDE_AGENT = "claude_agent"
    CLAUDE_COMMAND = "claude_command"
    CLAUDE_HOOK = "claude_hook"
    CLAUDE_RULE = "claude_rule"
    CLAUDE_SETTINGS = "claude_settings"
    CLAUDE_SKILL = "claude_skill"
    CODEX_RULE = "codex_rule"
    CODEX_SETTINGS = "codex_settings"
    CODEX_SKILL = "codex_skill"
    CURSOR_AGENT = "cursor_agent"
    CURSOR_COMMAND = "cursor_command"
    CURSOR_HOOK = "cursor_hook"
    CURSOR_RULE = "cursor_rule"
    CURSOR_SKILL = "cursor_skill"
    UNIVERSAL_AGENT_INSTRUCTIONS = "universal_agent_instructions"


class OutputFile(BaseModel):
    """Describe a generated file or symlink and its canonical source."""

    model_config = ConfigDict(frozen=True)

    target_path: Path
    content: str
    kind: OutputKind
    slug: str
    source_path: Path | None
    link_target: Path | None = None


class DiffEntry(BaseModel):
    """Describe generated output whose on-disk state differs."""

    model_config = ConfigDict(frozen=True)

    output: OutputFile
    existing: str | None
