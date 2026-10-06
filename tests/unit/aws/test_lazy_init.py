from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.config import Config

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.kms import KMS_TEST_CONTEXT
from tests.models.kms import KMSClientFactory


class TestAWSAdapterLazyInit:
    """Test the lazy boto3 client construction path."""

    @pytest.mark.parametrize(
        ("connect_timeout", "read_timeout", "attempts"),
        [(2, 5, 2), (5, 15, 3)],
        ids=["defaults", "configured_bounds"],
    )
    def test_sync_kms_builds_boto3_client_on_first_use(
        self,
        kms_client_factory: KMSClientFactory,
        monkeypatch: pytest.MonkeyPatch,
        connect_timeout: int,
        read_timeout: int,
        attempts: int,
    ) -> None:
        """Test that the first call to ``encrypt()`` builds a boto3 KMS client and caches it."""

        monkeypatch.setattr(settings, "AWS_KMS_CONNECT_TIMEOUT_SECONDS", connect_timeout)
        monkeypatch.setattr(settings, "AWS_KMS_READ_TIMEOUT_SECONDS", read_timeout)
        monkeypatch.setattr(settings, "AWS_KMS_MAX_ATTEMPTS", attempts)

        AWSAdapter.encrypt(b"payload", associated_data=KMS_TEST_CONTEXT)

        assert len(kms_client_factory.calls) == 1

        service, config, client_kwargs = kms_client_factory.calls[0]

        assert service == "kms"
        assert client_kwargs["region_name"] == "us-east-1"
        assert isinstance(config, Config)
        assert config.connect_timeout == connect_timeout
        assert config.read_timeout == read_timeout
        assert config.retries == {"mode": "standard", "total_max_attempts": attempts}
        assert AWSAdapter._sync_client is not None

        AWSAdapter.encrypt(b"payload-2", associated_data=KMS_TEST_CONTEXT)

        assert len(kms_client_factory.calls) == 1

    def test_concurrent_first_use_builds_one_client(
        self, concurrent_kms_client_factory: KMSClientFactory
    ) -> None:
        """Return one SDK client to all cold callers and bypass locking once it is cached."""

        factory = concurrent_kms_client_factory

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(AWSAdapter.sync_kms) for _ in range(8)]

            try:
                assert factory.wait_for_client_requests(len(futures))
            finally:
                factory.release.set()

            clients = [future.result(timeout=5) for future in futures]

        assert len(factory.calls) == 1
        assert all(client is clients[0] for client in clients)
        assert AWSAdapter.sync_kms() is clients[0]
        assert factory.client_requests == len(futures)
