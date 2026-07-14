from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict

__all__ = ["Command", "ExitCode", "RuntimeArguments"]


class ExitCode(IntEnum):
    """Define agent-sync process exit codes."""

    SUCCESS = 0
    DIFFERENCES = 1
    CONFIGURATION_ERROR = 2


class Command(StrEnum):
    """Define supported agent-sync commands."""

    SYNC = "sync"
    VALIDATE = "validate"


class RuntimeArguments(BaseModel):
    """Contain validated agent-sync command-line arguments."""

    model_config = ConfigDict(frozen=True)

    command: Command
    dry_run: bool
