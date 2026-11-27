import os
import subprocess
import sys

import pytest

pytest.importorskip("boto3")

from tests.models.kms import KMS_KEY_ARN
from tests.unit.utils import AWS_FORK_SCRIPT


@pytest.mark.skipif(not hasattr(os, "fork"), reason="The platform cannot fork.")
class TestForkReset:
    """Test that a forked child starts from none of the KMS state its parent held."""

    def test_child_starts_without_parent_state(self, pytestconfig: pytest.Config):
        """Test that a child forked mid-lock gets a free lock, no client and no held keys."""

        result = subprocess.run(
            [sys.executable, "-W", "default", "-c", AWS_FORK_SCRIPT],
            capture_output=True,
            text=True,
            env={**os.environ, "AWS_KMS_KEY_ARN": KMS_KEY_ARN},
            cwd=pytestconfig.rootpath,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert result.stderr == ""
