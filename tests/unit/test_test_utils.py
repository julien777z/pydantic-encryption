from typing import Any

import pytest

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.test_utils import reset_test_state


class TestResetTestState:
    """Test that reset_test_state() drops every adapter's lazily-cached client."""

    def test_reset_clears_fernet_clients(self) -> None:
        """Test that reset_test_state() clears the FernetAdapter._clients cache."""

        FernetAdapter._clients["sentinel"] = "anything"  # type: ignore[assignment]

        reset_test_state()

        assert FernetAdapter._clients == {}

    def test_reset_clears_aws_adapter_state(self) -> None:
        """Test that reset_test_state() clears the AWSAdapter sync + async client cache."""

        pytest.importorskip("boto3")
        pytest.importorskip("aioboto3")

        from pydantic_encryption.adapters.encryption.aws import AWSAdapter

        AWSAdapter._sync_client = "sync"  # type: ignore[assignment]
        AWSAdapter._async_client = "async"  # type: ignore[assignment]
        AWSAdapter._async_loop = "loop"  # type: ignore[assignment]
        AWSAdapter._async_init_lock = "lock"  # type: ignore[assignment]

        reset_test_state()

        assert AWSAdapter._sync_client is None
        assert AWSAdapter._async_client is None
        assert AWSAdapter._async_loop is None
        assert AWSAdapter._async_init_lock is None

    def test_reset_is_safe_when_aws_extras_not_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that reset_test_state() is a no-op when the AWS extras (boto3/aioboto3) are absent."""

        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "pydantic_encryption.adapters.encryption.aws":
                raise ImportError("aws extras not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        reset_test_state()
