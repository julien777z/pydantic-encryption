import json
import logging
import subprocess
import sys
from typing import Final

from models import TypeCompleteness, VerifyTypesReport

logger = logging.getLogger(__name__)

PACKAGE_NAME: Final[str] = "pydantic_encryption"
# botocore ships no type information, so verifytypes reads every botocore class in a public
# signature as unknown even though consumers' type checkers resolve it from botocore's source.
UNTYPED_DEPENDENCY_SYMBOLS: Final[frozenset[str]] = frozenset(
    {
        "pydantic_encryption.AWSAdapter",
        "pydantic_encryption.adapters.encryption.aws.AWSAdapter",
        "pydantic_encryption.adapters.encryption.aws.AWSAdapter.sync_kms",
        "pydantic_encryption.adapters.encryption.aws.kms_transport_config",
    }
)


def verify_type_completeness() -> TypeCompleteness:
    """Return pyright's type completeness report for the package's public interface."""

    completed = subprocess.run(
        ["pyright", "--verifytypes", PACKAGE_NAME, "--ignoreexternal", "--outputjson"],
        capture_output=True,
        text=True,
        check=False,
    )
    report: VerifyTypesReport = json.loads(completed.stdout)

    return report["typeCompleteness"]


def is_type_complete(completeness: TypeCompleteness) -> bool:
    """Return whether exactly the untyped-dependency symbols are left incompletely typed."""

    incomplete = {
        symbol["name"]
        for symbol in completeness["symbols"]
        if symbol["isExported"] and (not symbol["isTypeKnown"] or symbol["isTypeAmbiguous"])
    }

    logger.info("Type completeness score: %.2f%%", completeness["completenessScore"] * 100)

    for name in sorted(incomplete - UNTYPED_DEPENDENCY_SYMBOLS):
        logger.error("Incompletely typed public symbol: %s", name)

    for name in sorted(UNTYPED_DEPENDENCY_SYMBOLS - incomplete):
        logger.error("Fully typed now, so drop it from UNTYPED_DEPENDENCY_SYMBOLS: %s", name)

    return incomplete == UNTYPED_DEPENDENCY_SYMBOLS


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    sys.exit(0 if is_type_complete(verify_type_completeness()) else 1)
