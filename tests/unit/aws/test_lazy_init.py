from botocore.config import Config
import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from tests.kms import FakeSyncKMSClient, KMS_TEST_CONTEXT, configure_kms_settings, reset_adapter_state


class TestAWSAdapterLazyInit:
    """Test the lazy boto3 client construction path."""

    def test_sync_kms_builds_boto3_client_on_first_use(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that the first call to ``encrypt()`` builds a boto3 KMS client and caches it."""

        reset_adapter_state()

        configure_kms_settings(monkeypatch)

        captured_calls: list[tuple[str, Config, dict[str, str]]] = []

        def fake_boto3_client(service: str, *, config: Config, **kwargs: str) -> FakeSyncKMSClient:
            captured_calls.append((service, config, kwargs))

            return FakeSyncKMSClient()

        monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.boto3.client", fake_boto3_client)

        AWSAdapter.encrypt(b"payload", associated_data=KMS_TEST_CONTEXT)

        assert len(captured_calls) == 1

        service, config, client_kwargs = captured_calls[0]

        assert service == "kms"
        assert client_kwargs["region_name"] == "us-east-1"
        assert isinstance(config, Config)
        assert config.connect_timeout == 2
        assert config.read_timeout == 5
        assert config.retries == {"mode": "standard", "total_max_attempts": 2}
        assert AWSAdapter._sync_client is not None

        AWSAdapter.encrypt(b"payload-2", associated_data=KMS_TEST_CONTEXT)

        assert len(captured_calls) == 1

        reset_adapter_state()
