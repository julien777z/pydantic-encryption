from pathlib import Path

from pydantic import BaseModel, ConfigDict

__all__ = ["Workspace"]


class Workspace(BaseModel):
    """Provide canonical and generated paths for one repository."""

    model_config = ConfigDict(frozen=True)

    root: Path

    @property
    def agents(self) -> Path:
        """Return the canonical agent directory."""

        return self.root / ".agents"

    @property
    def settings(self) -> Path:
        """Return the canonical settings directory."""

        return self.agents / "settings"

    @property
    def models(self) -> Path:
        """Return the canonical agent-model directory."""

        return self.agents / "models"
