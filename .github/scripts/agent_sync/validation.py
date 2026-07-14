import logging

from agent_sync.models.settings import AgentSyncSettings
from agent_sync.models.validation import ValidationCheck, ValidationContext
from agent_sync.models.workspace import Workspace

__all__ = ["run_validations"]

logger = logging.getLogger(__name__)


def run_validations(workspace: Workspace, settings: AgentSyncSettings) -> None:
    """Run every registered canonical agent-sync validation."""

    context = ValidationContext(workspace=workspace, settings=settings)
    for check in validation_checks():
        check.run(context)
        logger.info("Validation passed: %s", check.name)


def validation_checks() -> tuple[ValidationCheck, ...]:
    """Return the ordered registry of canonical validation checks."""

    return ()
