import logging
import re
from pathlib import Path
from typing import Final, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from agent_sync.models.frontmatter import RuleFrontMatter

__all__ = [
    "assemble_codex_skill",
    "derive_description",
    "ensure_trailing_newline",
    "has_front_matter",
    "normalize_rule_source",
    "normalize_text",
    "parse_markdown_file",
    "render_front_matter",
    "slug_to_codex_name",
    "validate_slug",
]

logger = logging.getLogger(__name__)
SAFE_SLUG_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
FrontMatterModel = TypeVar("FrontMatterModel", bound=BaseModel)


class FrontMatterDumper(yaml.SafeDumper):
    """Render multiline strings as YAML literal blocks."""


def represent_multiline_str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    """Render one string using an appropriate YAML scalar style."""

    style = "|" if "\n" in value else None

    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


FrontMatterDumper.add_representer(str, represent_multiline_str)


def parse_markdown_file(path: Path, model: type[FrontMatterModel]) -> tuple[FrontMatterModel, str]:
    """Parse and validate a Markdown file's optional YAML front matter."""

    if not path.exists():
        return model(), ""

    content = path.read_text(encoding="utf-8")
    lines = content.splitlines()

    if not lines or lines[0] != "---":
        return model(), normalize_text(content)

    try:
        end_index = lines.index("---", 1)
    except ValueError:
        logger.warning("Unterminated front matter in %s", path)

        return model(), normalize_text(content)

    body = normalize_text("\n".join(lines[end_index + 1 :]))
    front_matter_content = "\n".join(lines[1:end_index]).strip()

    if not front_matter_content:
        return model(), body

    try:
        front_matter = model.model_validate(yaml.safe_load(front_matter_content))
    except (ValidationError, yaml.YAMLError) as exc:
        logger.warning("Invalid front matter in %s: %s", path, exc)

        return model(), body

    return front_matter, body


def normalize_rule_source(front_matter: RuleFrontMatter, body: str) -> str:
    """Render a canonical rule with deterministic front matter."""

    return render_front_matter(front_matter, body, exclude={"name"})


def assemble_codex_skill(body: str, name: str, description: str) -> str:
    """Build a Codex skill file with required front matter."""

    front_matter = f"---\nname: {yaml_quote(name)}\ndescription: {yaml_quote(description)}\n---\n\n"

    return front_matter + ensure_trailing_newline(body)


def render_front_matter(
    front_matter: BaseModel,
    body: str,
    *,
    exclude: set[str] | None = None,
) -> str:
    """Serialize a typed model as YAML front matter."""

    values = front_matter.model_dump(
        by_alias=True,
        exclude=exclude,
        exclude_none=True,
    )
    front = yaml.dump(
        values,
        Dumper=FrontMatterDumper,
        sort_keys=False,
        default_flow_style=False,
        width=10_000,
        allow_unicode=True,
    ).strip()
    output = f"---\n{front}\n---\n"

    if body:
        output += "\n" + body

    return ensure_trailing_newline(output)


def has_front_matter(front_matter: BaseModel, *, exclude: set[str] | None = None) -> bool:
    """Return whether a typed model has serializable front-matter values."""

    return bool(
        front_matter.model_dump(
            by_alias=True,
            exclude=exclude,
            exclude_none=True,
        )
    )


def normalize_text(value: str) -> str:
    """Strip surrounding whitespace from Markdown content."""

    return value.strip()


def slug_to_codex_name(slug: str) -> str:
    """Convert a canonical slug into a Codex-compatible name."""

    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", slug).strip("-").lower()

    return normalized or slug


def derive_description(content: str) -> str:
    """Extract a description from the first prose line or header."""

    first_header = next(
        (
            " ".join(line.lstrip("#").strip().split())
            for raw_line in content.splitlines()
            if (line := raw_line.strip()).startswith("#")
        ),
        None,
    )
    first_prose = next(
        (
            " ".join(line.split())
            for raw_line in content.splitlines()
            if (line := raw_line.strip()) and not line.startswith("#")
        ),
        None,
    )

    return first_prose or first_header or "Project conventions."


def ensure_trailing_newline(text: str) -> str:
    """Ensure generated text ends with one newline."""

    return text if text.endswith("\n") else text + "\n"


def validate_slug(slug: str, source_path: Path) -> str:
    """Validate a canonical filesystem slug."""

    if not SAFE_SLUG_PATTERN.match(slug):
        raise ValueError(f"Invalid slug '{slug}' from {source_path}")

    return slug


def yaml_quote(value: str) -> str:
    """Quote a string for a YAML scalar."""

    escaped = value.replace("\\", "\\\\").replace('"', '\\"')

    return f'"{escaped}"'
