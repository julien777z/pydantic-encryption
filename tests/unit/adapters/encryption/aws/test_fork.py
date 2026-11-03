import os

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from tests.cases import SEALED_CONTEXT
from tests.models.kms import FakeSyncKMSClient


@pytest.mark.skipif(not hasattr(os, "fork"), reason="The platform cannot fork.")
class TestForkReset:
    """Test that a forked child starts from none of the KMS state its parent held."""

    def test_child_starts_without_parent_state(self, fake_sync_kms: FakeSyncKMSClient):
        """Test that a child forked mid-lock gets a free lock, no client and no held keys."""

        sealed = AWSAdapter.encrypt("secret data", associated_data=SEALED_CONTEXT)
        AWSAdapter.decrypt(sealed, associated_data=SEALED_CONTEXT)

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
        assert AWSAdapter.kms_client is fake_sync_kms
        assert AWSAdapter.encrypt_key is not None
