import logging
from pathlib import Path

from agent_sync.exceptions import AgentSyncConfigError
from agent_sync.markdown import parse_markdown_file, validate_slug
from agent_sync.models.frontmatter import SkillFrontMatter
from agent_sync.models.outputs import OutputFile, OutputKind
from agent_sync.models.providers.providers import Provider
from agent_sync.models.workspace import Workspace

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

        front_matter, _ = parse_markdown_file(source_path, SkillFrontMatter)
        validate_canonical_skill_metadata(front_matter, source_path)
        outputs.extend(generate_skill_links(workspace, skill_dir, source_path, slug))
        outputs.append(
            OutputFile(
                target_path=workspace.root / ".codex" / "skills" / slug,
                content="",
                kind=OutputKind.CODEX_SKILL,
                slug=slug,
                source_path=source_path,
                link_target=skill_dir,
            )
        )

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


def validate_canonical_skill_metadata(front_matter: SkillFrontMatter, source_path: Path) -> None:
    """Require metadata shared by every canonical skill."""

    if not front_matter.name or not front_matter.description:
        raise AgentSyncConfigError(
            f"Skill {source_path} must define non-empty name and description front matter"
        )

    if front_matter.name != source_path.parent.name:
        raise AgentSyncConfigError(
            f"Skill {source_path} must use directory name {source_path.parent.name!r} "
            f"as its front matter name, not {front_matter.name!r}"
        )

def skill_link_kind(provider: Provider) -> OutputKind:
    """Return the directory-link output kind for one provider."""

    match provider:
        case Provider.CLAUDE:
            return OutputKind.CLAUDE_SKILL
        case Provider.CURSOR:
            return OutputKind.CURSOR_SKILL
        case Provider.CODEX:
            raise ValueError("Codex skills use their dedicated directory-link output")
