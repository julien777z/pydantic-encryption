import os

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.cases import SEALED_CONTEXT
from tests.models.kms import FakeSyncKMSClient, KMS_KEY_ARN
from tests.unit.utils import check_in_fresh_process


def check_kms_fork() -> None:
    """Verify that KMS state stays with the parent and the child receives fresh locks."""

    client = FakeSyncKMSClient()
    settings.AWS_KMS_KEY_ARN = KMS_KEY_ARN
    settings.AWS_KMS_ENCRYPT_KEY_ARN = None
    settings.AWS_KMS_DECRYPT_KEY_ARN = None
    AWSAdapter.kms_client = client

    sealed = AWSAdapter.encrypt("secret data", associated_data=SEALED_CONTEXT)
    AWSAdapter.decrypt(sealed, associated_data=SEALED_CONTEXT)

    timer = AWSAdapter.expiry_timer

    assert timer is not None

    timer.cancel()
    timer.join(timeout=5)

    assert not timer.is_alive()

    with AWSAdapter.cache_lock:
        child = os.fork()

        if child == 0:
            is_fresh = (
                AWSAdapter.cache_lock.acquire(blocking=False)
                and AWSAdapter.kms_client is None
                and AWSAdapter.encrypt_key is None
                and not AWSAdapter.unwrapped_keys
            )
            os._exit(0 if is_fresh else 1)

    _, status = os.waitpid(child, 0)

    assert os.waitstatus_to_exitcode(status) == 0
    assert AWSAdapter.kms_client is client
    assert AWSAdapter.encrypt_key is not None


@pytest.mark.skipif(not hasattr(os, "fork"), reason="The platform cannot fork.")
class TestForkReset:
    """Test that a forked child starts from none of the KMS state its parent held."""

    def test_child_starts_without_parent_state(self):
        """Test that a child forked mid-lock gets a free lock, no client and no held keys."""

        check_in_fresh_process(check_kms_fork)
