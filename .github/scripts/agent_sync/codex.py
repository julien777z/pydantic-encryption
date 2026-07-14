import json
import re
import tomllib
from collections.abc import Iterator
from typing import Final, TypedDict

from agent_sync.exceptions import AgentSyncConfigError
from agent_sync.markdown import ensure_trailing_newline
from agent_sync.models.providers.codex import CodexSettings

__all__ = ["generate_codex_config"]


class CodexTomlConfig(TypedDict):
    """Define the managed Codex TOML block format."""

    settings_start_marker: str
    settings_end_marker: str
    setting_pattern: re.Pattern[str]


CODEX_TOML_CONFIG: Final[CodexTomlConfig] = CodexTomlConfig(
    settings_start_marker="# >>> agent-sync managed Codex settings >>>",
    settings_end_marker="# <<< agent-sync managed Codex settings <<<",
    setting_pattern=re.compile(
        r"^\s*(?:approval_policy|model|project_doc_max_bytes|sandbox_mode)\s*="
    ),
)


def generate_codex_config(settings: CodexSettings, existing: str | None) -> str:
    """Replace the managed Codex settings block and preserve unrelated TOML."""

    current = existing or ""
    block = render_codex_settings_block(settings)
    lines = current.splitlines(keepends=True)
    start_index, end_index = find_managed_marker_indexes(lines)

    if start_index is not None and end_index is not None:
        rendered = replace_managed_block(lines, block, start_index, end_index)
        rendered = remove_unmanaged_codex_settings(rendered)
    else:
        rendered = insert_top_level_toml_block(remove_unmanaged_codex_settings(current), block)
    rendered = ensure_trailing_newline(rendered)

    try:
        tomllib.loads(rendered)
    except tomllib.TOMLDecodeError as exc:
        raise AgentSyncConfigError(f"Generated .codex/config.toml is invalid TOML: {exc}") from exc

    return rendered


def find_managed_marker_indexes(lines: list[str]) -> tuple[int | None, int | None]:
    """Find the single valid pair of standalone managed marker lines."""

    start_marker = CODEX_TOML_CONFIG["settings_start_marker"]
    end_marker = CODEX_TOML_CONFIG["settings_end_marker"]
    start_indexes = [
        index
        for index, (line, is_normal) in enumerate(iter_toml_lines(lines))
        if is_normal and line.strip() == start_marker
    ]
    end_indexes = [
        index
        for index, (line, is_normal) in enumerate(iter_toml_lines(lines))
        if is_normal and line.strip() == end_marker
    ]

    if len(start_indexes) != len(end_indexes) or len(start_indexes) > 1:
        raise AgentSyncConfigError(
            ".codex/config.toml has malformed or duplicate agent-sync Codex settings markers"
        )
    if not start_indexes:
        return None, None
    if end_indexes[0] < start_indexes[0]:
        raise AgentSyncConfigError(
            ".codex/config.toml has agent-sync Codex settings markers in the wrong order"
        )
    if end_indexes[0] >= find_first_toml_table(lines):
        raise AgentSyncConfigError(
            ".codex/config.toml has agent-sync Codex settings markers outside top-level TOML"
        )

    return start_indexes[0], end_indexes[0]


def replace_managed_block(
    lines: list[str],
    block: str,
    start_index: int,
    end_index: int,
) -> str:
    """Replace the single well-formed managed settings block."""

    end_marker = CODEX_TOML_CONFIG["settings_end_marker"]
    end_marker_index = lines[end_index].index(end_marker)
    suffix = lines[end_index][end_marker_index + len(end_marker) :]

    return "".join((*lines[:start_index], block, suffix, *lines[end_index + 1 :]))


def insert_top_level_toml_block(current: str, block: str) -> str:
    """Insert a top-level TOML block before the first table declaration."""

    lines = current.splitlines(keepends=True)
    table_index = find_first_toml_table(lines)

    prefix = "".join(lines[:table_index]).rstrip("\n")
    suffix = "".join(lines[table_index:]).lstrip("\n")

    return "\n\n".join(part for part in (prefix, block, suffix) if part)


def remove_unmanaged_codex_settings(current: str) -> str:
    """Remove top-level Codex settings superseded by the canonical source."""

    lines = current.splitlines(keepends=True)
    table_index = find_first_toml_table(lines)
    managed_start_index, managed_end_index = find_managed_marker_indexes(lines)
    retained_lines = [
        line
        for index, (line, is_normal) in enumerate(iter_toml_lines(lines))
        if index >= table_index
        or (
            managed_start_index is not None
            and managed_end_index is not None
            and managed_start_index <= index <= managed_end_index
        )
        or not (is_normal and CODEX_TOML_CONFIG["setting_pattern"].match(line))
    ]

    return "".join(retained_lines)


def find_first_toml_table(lines: list[str]) -> int:
    """Find the first real TOML table while ignoring strings and arrays."""

    for index, (line, is_normal) in enumerate(iter_toml_lines(lines)):
        if is_normal and line.lstrip().startswith("["):
            return index

    return len(lines)


def iter_toml_lines(lines: list[str]) -> Iterator[tuple[str, bool]]:
    """Yield each line with whether it begins in normal top-level TOML syntax."""

    string_kind: str | None = None
    array_depth = 0
    for line in lines:
        is_normal = string_kind is None and array_depth == 0
        yield line, is_normal
        string_kind, array_depth = scan_toml_line(line, string_kind, array_depth)


def scan_toml_line(
    line: str,
    string_kind: str | None,
    array_depth: int,
) -> tuple[str | None, int]:
    """Track TOML string and array state across one line."""

    index = 0
    while index < len(line):
        if string_kind == "multiline_basic":
            if line.startswith('"""', index) and not is_escaped(line, index):
                string_kind = None
                index += 3
            else:
                index += 1
            continue
        if string_kind == "multiline_literal":
            if line.startswith("'''", index):
                string_kind = None
                index += 3
            else:
                index += 1
            continue
        if string_kind == "basic":
            if line[index] == '"' and not is_escaped(line, index):
                string_kind = None
            index += 1
            continue
        if string_kind == "literal":
            if line[index] == "'":
                string_kind = None
            index += 1
            continue

        if line[index] == "#":
            break
        if line.startswith('"""', index):
            string_kind = "multiline_basic"
            index += 3
            continue
        if line.startswith("'''", index):
            string_kind = "multiline_literal"
            index += 3
            continue
        if line[index] == '"':
            string_kind = "basic"
        elif line[index] == "'":
            string_kind = "literal"
        elif line[index] == "[":
            array_depth += 1
        elif line[index] == "]":
            array_depth = max(0, array_depth - 1)
        index += 1

    return string_kind, array_depth


def is_escaped(value: str, index: int) -> bool:
    """Return whether a character at index has an odd backslash prefix."""

    backslashes = 0
    for preceding_index in range(index - 1, -1, -1):
        if value[preceding_index] != "\\":
            break
        backslashes += 1

    return bool(backslashes % 2)


def render_codex_settings_block(settings: CodexSettings) -> str:
    """Render canonical Codex settings as a marked TOML block."""

    lines = [CODEX_TOML_CONFIG["settings_start_marker"]]
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
            CODEX_TOML_CONFIG["settings_end_marker"],
        )
    )

    return "\n".join(lines)
