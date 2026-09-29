import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters import registry
from pydantic_encryption.adapters.encryption.aws import AWSAdapter


class TestLoadAwsAdapter:
    """Test the lazily registered AWS adapter factory."""

    def test_imports_adapter(self):
        """Test that the AWS factory imports and returns the AWSAdapter class."""

        assert registry.load_aws_adapter() is AWSAdapter
