from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.config import Config

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings
from tests.cases import SEALED_CONTEXT
from tests.models.kms import KMSClientFactory


class TestLazyInit:
    """Test that the adapter builds its boto3 KMS client once, on first use, from the configured settings."""

    @pytest.mark.parametrize(
        ("connect_timeout", "read_timeout", "attempts"),
        [(2, 5, 2), (5, 15, 3)],
        ids=["defaults", "configured-bounds"],
    )
    def test_first_use_builds_configured_client(
        self,
        kms_client_factory: KMSClientFactory,
        monkeypatch: pytest.MonkeyPatch,
        connect_timeout: int,
        read_timeout: int,
        attempts: int,
    ) -> None:
        """Test that the first seal builds a client with the configured transport, which later seals reuse."""

        monkeypatch.setattr(settings, "AWS_KMS_CONNECT_TIMEOUT_SECONDS", connect_timeout)
        monkeypatch.setattr(settings, "AWS_KMS_READ_TIMEOUT_SECONDS", read_timeout)
        monkeypatch.setattr(settings, "AWS_KMS_MAX_ATTEMPTS", attempts)

        AWSAdapter.encrypt(b"secret data", associated_data=SEALED_CONTEXT)
        AWSAdapter.encrypt(b"more secret data", associated_data=SEALED_CONTEXT)

        assert len(kms_client_factory.calls) == 1

        service, config, client_kwargs = kms_client_factory.calls[0]

        assert service == "kms"
        assert client_kwargs["region_name"] == settings.AWS_KMS_REGION
        assert isinstance(config, Config)
        assert config.connect_timeout == connect_timeout
        assert config.read_timeout == read_timeout
        assert config.retries == {"mode": "standard", "total_max_attempts": attempts}

    def test_concurrent_first_use_builds_one_client(
        self, concurrent_kms_client_factory: KMSClientFactory
    ) -> None:
        """Test that cold callers racing the first use all receive the one client it builds."""

        factory = concurrent_kms_client_factory

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(AWSAdapter.client) for _ in range(8)]

            try:
                assert factory.wait_for_client_requests(len(futures))
            finally:
                factory.release.set()

            clients = [future.result(timeout=5) for future in futures]

        assert len(factory.calls) == 1
        assert all(client is clients[0] for client in clients)
        assert AWSAdapter.client() is clients[0]
        assert factory.client_requests == len(futures)

    @pytest.mark.parametrize(
        "unset",
        ["AWS_KMS_REGION", "AWS_KMS_ACCESS_KEY_ID", "AWS_KMS_SECRET_ACCESS_KEY", "AWS_KMS_KEY_ARN"],
        ids=["region", "access-key", "secret-key", "key-arn"],
    )
    def test_incomplete_settings_refused(
        self, kms_client_factory: KMSClientFactory, monkeypatch: pytest.MonkeyPatch, unset: str
    ) -> None:
        """Test that building the client refuses when a required KMS setting is missing."""

        monkeypatch.setattr(settings, unset, None)

        with pytest.raises(ValueError, match="AWS KMS requires"):
            AWSAdapter.client()

        assert kms_client_factory.calls == []
