from pydantic import BaseModel, ConfigDict, Field

from agent_sync.models.providers.providers import Provider

__all__ = ["AgentFrontMatter", "CommandFrontMatter", "RuleFrontMatter", "SkillFrontMatter"]


class SkillFrontMatter(BaseModel):
    """Validate canonical skill front matter."""

    model_config = ConfigDict(extra="allow", strict=True)

    name: str | None = None
    description: str | None = None


class CommandFrontMatter(BaseModel):
    """Validate canonical command front matter."""

    model_config = ConfigDict(extra="allow", strict=True, populate_by_name=True)

    allowed_tools: str | None = Field(default=None, alias="allowed-tools")
    variants: dict[Provider, str] | None = None


class AgentFrontMatter(BaseModel):
    """Validate canonical agent front matter."""

    model_config = ConfigDict(extra="allow", strict=True)

    name: str | None = None
    description: str | None = None
    tools: str | None = None
    model: str | None = None


class RuleFrontMatter(BaseModel):
    """Validate canonical rule front matter."""

    model_config = ConfigDict(extra="allow", strict=True, populate_by_name=True)

    description: str | None = None
    globs: str | list[str] | None = None
    always_apply: bool = Field(default=True, alias="alwaysApply")
    starlark: str | None = None
