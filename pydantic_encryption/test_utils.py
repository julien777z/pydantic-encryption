from pydantic_encryption.adapters.encryption.fernet import FernetAdapter

__all__ = ["reset_test_state"]


def reset_test_state() -> None:
    """Drop every adapter's lazily-cached client so the next call rebuilds against current settings."""

    FernetAdapter._clients.clear()

    try:
        from pydantic_encryption.adapters.encryption.aws import AWSAdapter
    except ImportError:
        return

    AWSAdapter._sync_client = None
    AWSAdapter._async_client = None
    AWSAdapter._async_loop = None
    AWSAdapter._async_init_lock = None
