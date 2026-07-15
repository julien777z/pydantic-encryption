import argparse
import logging
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict

from agent_sync.configuration import (
    AgentSyncConfigError,
    load_agent_model_overrides,
    load_settings,
)
from agent_sync.generation import generate_outputs
from agent_sync.models.configuration import Workspace
from agent_sync.reconciliation import (
    apply_changes,
    compute_diffs,
    compute_stale_paths,
    report_diffs,
)

__all__ = ["main"]


logger = logging.getLogger(__name__)

WORKSPACE: Final[Workspace] = Workspace(root=Path(__file__).resolve().parents[3])


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


def main(arguments: list[str] | None = None) -> int:
    """Run the requested agent-sync command."""

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parsed_arguments = parse_arguments(arguments)

    if not WORKSPACE.agents.exists():
        logger.error("Missing .agents directory in %s", WORKSPACE.root)

        return ExitCode.CONFIGURATION_ERROR

    try:
        settings = load_settings(WORKSPACE)

        if parsed_arguments.command is Command.VALIDATE:
            return ExitCode.SUCCESS

        model_overrides = load_agent_model_overrides(WORKSPACE)
        outputs = generate_outputs(WORKSPACE, settings, model_overrides)
    except AgentSyncConfigError as exc:
        logger.error("%s", exc)

        return ExitCode.CONFIGURATION_ERROR

    diffs = compute_diffs(WORKSPACE, outputs)
    stale_paths = compute_stale_paths(WORKSPACE, outputs)

    if not diffs and not stale_paths:
        logger.info("No differences found")

        return ExitCode.SUCCESS

    if parsed_arguments.dry_run:
        report_diffs(diffs, stale_paths)

        return ExitCode.DIFFERENCES

    apply_changes(WORKSPACE, diffs, stale_paths)
    logger.info(
        "Sync complete: %d output changes and %d stale paths removed",
        len(diffs),
        len(stale_paths),
    )

    return ExitCode.SUCCESS


def parse_arguments(arguments: list[str] | None) -> RuntimeArguments:
    """Parse agent-sync command-line arguments."""

    parser = argparse.ArgumentParser(description="Sync canonical agent configuration")

    subparsers = parser.add_subparsers(dest="command", required=True)

    sync_parser = subparsers.add_parser(Command.SYNC.value, help="Generate provider outputs")

    sync_parser.add_argument("--dry-run", action="store_true", help="Report differences only")

    validate_parser = subparsers.add_parser(
        Command.VALIDATE.value,
        help="Validate canonical configuration",
    )

    validate_parser.set_defaults(dry_run=False)

    parsed_arguments = parser.parse_args(arguments)

    return RuntimeArguments(
        command=Command(parsed_arguments.command),
        dry_run=parsed_arguments.dry_run,
    )
