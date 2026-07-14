import logging
from pathlib import Path

from agent_sync.markdown import (
    SAFE_SLUG_PATTERN,
    assemble_codex_skill,
    derive_description,
    ensure_trailing_newline,
    parse_markdown_file,
    slug_to_codex_name,
    validate_slug,
)
from agent_sync.models.frontmatter import SkillFrontMatter
from agent_sync.models.outputs import OutputFile, OutputKind
from agent_sync.models.providers.providers import Provider
from agent_sync.models.workspace import Workspace
from agent_sync.storage import read_text

__all__ = ["generate_skill_outputs"]

logger = logging.getLogger(__name__)


def generate_skill_outputs(workspace: Workspace) -> list[OutputFile]:
    """Generate provider skill outputs from canonical skill directories."""

    skills_dir = workspace.agents / "skills"

    if not skills_dir.exists():
        return []

    outputs: list[OutputFile] = []
    for skill_dir in sorted(path for path in skills_dir.iterdir() if path.is_dir()):
        slug = validate_slug(skill_dir.name, skill_dir)
        source_path = skill_dir / "SKILL.md"

        if not source_path.exists():
            logger.warning("Missing SKILL.md in %s", skill_dir)
            continue

        front_matter, content = parse_markdown_file(source_path, SkillFrontMatter)
        codex_name = front_matter.name or slug_to_codex_name(slug)

        if not SAFE_SLUG_PATTERN.match(codex_name):
            logger.warning(
                "Invalid Codex skill name %r in %s; using canonical slug",
                codex_name,
                source_path,
            )
            codex_name = slug_to_codex_name(slug)
        codex_description = front_matter.description or derive_description(content)

        outputs.extend(generate_skill_links(workspace, skill_dir, source_path, slug))
        outputs.append(
            OutputFile(
                target_path=workspace.root / ".codex" / "skills" / codex_name / "SKILL.md",
                content=assemble_codex_skill(content, codex_name, codex_description),
                kind=OutputKind.CODEX_SKILL,
                slug=slug,
                source_path=source_path,
            )
        )
        outputs.extend(generate_codex_skill_assets(workspace, skill_dir, codex_name, slug))

    return outputs


def generate_skill_links(
    workspace: Workspace,
    skill_dir: Path,
    source_path: Path,
    slug: str,
) -> list[OutputFile]:
    """Generate Claude and Cursor directory links for one skill."""

    return [
        OutputFile(
            target_path=workspace.root / f".{provider.value}" / "skills" / slug,
            content="",
            kind=skill_link_kind(provider),
            slug=slug,
            source_path=source_path,
            link_target=skill_dir,
        )
        for provider in (Provider.CLAUDE, Provider.CURSOR)
    ]


def generate_codex_skill_assets(
    workspace: Workspace,
    skill_dir: Path,
    codex_name: str,
    slug: str,
) -> list[OutputFile]:
    """Generate non-Markdown Codex skill assets."""

    outputs: list[OutputFile] = []
    for asset_path in sorted(skill_dir.rglob("*")):
        if not asset_path.is_file() or asset_path.name == "SKILL.md":
            continue

        asset_content = read_text(asset_path)

        if asset_content is None:
            continue

        outputs.append(
            OutputFile(
                target_path=(
                    workspace.root / ".codex" / "skills" / codex_name / asset_path.relative_to(skill_dir)
                ),
                content=ensure_trailing_newline(asset_content),
                kind=OutputKind.CODEX_SKILL_ASSET,
                slug=slug,
                source_path=asset_path,
            )
        )

    return outputs


def skill_link_kind(provider: Provider) -> OutputKind:
    """Return the directory-link output kind for one provider."""

    match provider:
        case Provider.CLAUDE:
            return OutputKind.CLAUDE_SKILL
        case Provider.CURSOR:
            return OutputKind.CURSOR_SKILL
        case Provider.CODEX:
            raise ValueError("Codex skills are generated files, not directory links")
