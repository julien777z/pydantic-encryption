import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
import pytest_asyncio

pytest.importorskip("boto3")
pytest.importorskip("aioboto3")

from pydantic_encryption.adapters.encryption.aws import (
    CIPHERTEXT_MAGIC,
    CIPHERTEXT_VERSION,
    HEADER_LENGTH,
    NONCE_LENGTH,
    AWSAdapter,
)
from pydantic_encryption.types import EncryptedValue


def _reset_adapter_state() -> None:
    """Clear lazily-initialized KMS clients so each test starts fresh."""

    AWSAdapter._sync_client = None
    AWSAdapter._async_client = None
    AWSAdapter._async_client_ctx = None
    AWSAdapter._async_loop = None
    AWSAdapter._async_init_lock = None


class _FakeSyncKMSClient:
    """Stand-in for the sync boto3 KMS client; records calls and returns deterministic blobs."""

    def __init__(self, plaintext_data_key: bytes) -> None:
        self.plaintext_data_key = plaintext_data_key
        self.generate_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.next_wrapped_key: bytes = b"wrapped-key"

    def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        """Return a fixed plaintext key and a unique wrapped key per call."""

        self.generate_calls.append(kwargs)

        return {
            "Plaintext": self.plaintext_data_key,
            "CiphertextBlob": self.next_wrapped_key,
        }

    def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        """Return the fixed plaintext key for any wrapped key."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_data_key}


class _FakeAsyncKMSClient:
    """Stand-in for the aioboto3 KMS client; records calls and returns deterministic blobs."""

    def __init__(self, plaintext_data_key: bytes) -> None:
        self.plaintext_data_key = plaintext_data_key
        self.generate_calls: list[dict[str, Any]] = []
        self.decrypt_calls: list[dict[str, Any]] = []
        self.next_wrapped_key: bytes = b"wrapped-key"

    async def generate_data_key(self, **kwargs: Any) -> dict[str, bytes]:
        """Return a fixed plaintext key and a unique wrapped key per call."""

        self.generate_calls.append(kwargs)

        return {
            "Plaintext": self.plaintext_data_key,
            "CiphertextBlob": self.next_wrapped_key,
        }

    async def decrypt(self, **kwargs: Any) -> dict[str, bytes]:
        """Return the fixed plaintext key for any wrapped key."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_data_key}


@pytest.fixture
def fake_sync_kms(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeSyncKMSClient]:
    """Install a fake sync KMS client and seed AWS settings for the test process."""

    _reset_adapter_state()

    from pydantic_encryption.config import settings

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret-key")

    client = _FakeSyncKMSClient(plaintext_data_key=b"\x00" * 32)
    AWSAdapter._sync_client = client

    yield client

    _reset_adapter_state()


@pytest_asyncio.fixture
async def fake_async_kms(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[_FakeAsyncKMSClient]:
    """Install a fake async KMS client and seed AWS settings for the test process."""

    _reset_adapter_state()

    from pydantic_encryption.config import settings

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret-key")

    client = _FakeAsyncKMSClient(plaintext_data_key=b"\x00" * 32)
    AWSAdapter._async_client = client
    AWSAdapter._async_loop = asyncio.get_running_loop()

    yield client

    _reset_adapter_state()


class TestAWSAdapterEncrypt:
    """Test that encrypt() wraps a fresh data key under KMS and seals the plaintext with AES-GCM."""

    def test_encrypt_returns_encrypted_value_with_known_header(
        self, fake_sync_kms: _FakeSyncKMSClient
    ) -> None:
        """Test that encrypt() emits an EncryptedValue starting with the format magic + version."""

        result = AWSAdapter.encrypt(b"plaintext-payload")

        assert isinstance(result, EncryptedValue)

        blob = bytes(result)
        assert blob[0] == CIPHERTEXT_MAGIC
        assert blob[1] == CIPHERTEXT_VERSION

    def test_encrypt_calls_generate_data_key_once_per_call(
        self, fake_sync_kms: _FakeSyncKMSClient
    ) -> None:
        """Test that every sync encrypt() call requests a fresh KMS data key."""

        AWSAdapter.encrypt(b"payload-1")
        AWSAdapter.encrypt(b"payload-2")

        assert len(fake_sync_kms.generate_calls) == 2
        for call in fake_sync_kms.generate_calls:
            assert call["KeySpec"] == "AES_256"

    def test_encrypt_encodes_str_input(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that encrypt() encodes a str plaintext to utf-8 before sealing."""

        AWSAdapter.encrypt("plain-str")

        assert len(fake_sync_kms.generate_calls) == 1

    def test_encrypt_passthrough_for_already_encrypted_value(
        self, fake_sync_kms: _FakeSyncKMSClient
    ) -> None:
        """Test that encrypt() returns an existing EncryptedValue unchanged without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = AWSAdapter.encrypt(already_encrypted)

        assert result is already_encrypted
        assert fake_sync_kms.generate_calls == []


class TestAWSAdapterDecrypt:
    """Test that decrypt() unwraps the data key via KMS and AES-GCM-decrypts the payload."""

    def test_encrypt_then_decrypt_round_trips(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that decrypt(encrypt(x)) returns x as a str."""

        sealed = AWSAdapter.encrypt("hello world")

        result = AWSAdapter.decrypt(sealed)

        assert result == "hello world"
        assert len(fake_sync_kms.decrypt_calls) == 1

    def test_decrypt_each_call_invokes_kms(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that every decrypt() call routes through the KMS client (no plaintext cache)."""

        sealed_one = AWSAdapter.encrypt("first")
        fake_sync_kms.next_wrapped_key = b"wrapped-key-2"
        sealed_two = AWSAdapter.encrypt("second")

        AWSAdapter.decrypt(sealed_one)
        AWSAdapter.decrypt(sealed_one)
        AWSAdapter.decrypt(sealed_two)

        assert len(fake_sync_kms.decrypt_calls) == 3

    def test_decrypt_rejects_unrecognized_format(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that decrypt() raises ValueError when the magic byte does not match."""

        bogus = b"\x01" + b"\x00" * 32

        with pytest.raises(ValueError, match="Unrecognized ciphertext format"):
            AWSAdapter.decrypt(bogus)

    def test_decrypt_rejects_unsupported_version(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that decrypt() raises ValueError when the version byte is not supported."""

        unsupported = bytes([CIPHERTEXT_MAGIC, 0x99]) + b"\x00" * (HEADER_LENGTH + NONCE_LENGTH)

        with pytest.raises(ValueError, match="Unsupported"):
            AWSAdapter.decrypt(unsupported)

    def test_decrypt_passes_decrypt_arn_to_kms_when_configured(
        self,
        fake_sync_kms: _FakeSyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        from pydantic_encryption.config import settings

        sealed = AWSAdapter.encrypt("payload")
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        AWSAdapter.decrypt(sealed)

        assert fake_sync_kms.decrypt_calls[-1]["KeyId"] == "arn:aws:kms:us-east-1:000:key/dec"


class TestAWSAdapterAsync:
    """Test that async_encrypt / async_decrypt run the KMS round-trip on the event loop without threads."""

    @pytest.mark.asyncio
    async def test_async_encrypt_then_async_decrypt_round_trips(
        self, fake_async_kms: _FakeAsyncKMSClient
    ) -> None:
        """Test that async_decrypt(async_encrypt(x)) returns x as a str via the async client."""

        sealed = await AWSAdapter.async_encrypt("hello async")

        result = await AWSAdapter.async_decrypt(sealed)

        assert result == "hello async"
        assert len(fake_async_kms.generate_calls) == 1
        assert len(fake_async_kms.decrypt_calls) == 1

    @pytest.mark.asyncio
    async def test_async_encrypt_passthrough_for_already_encrypted_value(
        self, fake_async_kms: _FakeAsyncKMSClient
    ) -> None:
        """Test that async_encrypt() returns an existing EncryptedValue without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = await AWSAdapter.async_encrypt(already_encrypted)

        assert result is already_encrypted
        assert fake_async_kms.generate_calls == []

    @pytest.mark.asyncio
    async def test_async_decrypt_passes_decrypt_arn_when_configured(
        self,
        fake_async_kms: _FakeAsyncKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that async_decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        from pydantic_encryption.config import settings

        sealed = await AWSAdapter.async_encrypt("payload")
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        await AWSAdapter.async_decrypt(sealed)

        assert fake_async_kms.decrypt_calls[-1]["KeyId"] == "arn:aws:kms:us-east-1:000:key/dec"


class TestAWSAdapterValidation:
    """Test the ciphertext-format guards on the decrypt path."""

    def test_kms_client_build_raises_when_settings_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the lazy KMS client builder rejects unset AWS_KMS settings at use time."""

        _reset_adapter_state()

        from pydantic_encryption.config import settings

        for attr in (
            "AWS_KMS_KEY_ARN",
            "AWS_KMS_ENCRYPT_KEY_ARN",
            "AWS_KMS_DECRYPT_KEY_ARN",
            "AWS_KMS_REGION",
            "AWS_KMS_ACCESS_KEY_ID",
            "AWS_KMS_SECRET_ACCESS_KEY",
        ):
            monkeypatch.setattr(settings, attr, None)

        with pytest.raises(ValueError, match="AWS_KMS_REGION"):
            AWSAdapter.encrypt(b"payload")

    def test_decrypt_rejects_truncated_ciphertext(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that decrypt() raises when the input is shorter than the envelope header."""

        with pytest.raises(ValueError, match="too short"):
            AWSAdapter.decrypt(b"\xc0\x01")

    def test_decrypt_rejects_truncated_payload(self, fake_sync_kms: _FakeSyncKMSClient) -> None:
        """Test that decrypt() raises when the header announces more bytes than the blob carries."""

        import struct

        from pydantic_encryption.adapters.encryption.aws import (
            CIPHERTEXT_MAGIC,
            CIPHERTEXT_VERSION,
            HEADER_PACK_FORMAT,
        )

        # Header claims a 1024-byte wrapped key but the blob has no payload.
        truncated = struct.pack(HEADER_PACK_FORMAT, CIPHERTEXT_MAGIC, CIPHERTEXT_VERSION, 1024)

        with pytest.raises(ValueError, match="truncated"):
            AWSAdapter.decrypt(truncated)


class TestAWSAdapterLazyInit:
    """Test the lazy boto3 / aioboto3 client construction paths."""

    def test_sync_kms_builds_boto3_client_on_first_use(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the first call to ``encrypt()`` builds a boto3 KMS client and caches it."""

        _reset_adapter_state()

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
        monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
        monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access")
        monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret")

        captured_kwargs: list[dict[str, Any]] = []

        def fake_boto3_client(service: str, **kwargs: Any) -> Any:
            captured_kwargs.append({"service": service, **kwargs})
            return _FakeSyncKMSClient(plaintext_data_key=b"\x00" * 32)

        monkeypatch.setattr("pydantic_encryption.adapters.encryption.aws.boto3.client", fake_boto3_client)

        AWSAdapter.encrypt(b"payload")

        assert len(captured_kwargs) == 1
        assert captured_kwargs[0]["service"] == "kms"
        assert captured_kwargs[0]["region_name"] == "us-east-1"
        assert AWSAdapter._sync_client is not None

        AWSAdapter.encrypt(b"payload-2")

        assert len(captured_kwargs) == 1

        _reset_adapter_state()

    @pytest.mark.asyncio
    async def test_async_kms_opens_aioboto3_client_on_first_use(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the first ``async_encrypt()`` opens an aioboto3 KMS client and caches it for the loop."""

        _reset_adapter_state()

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
        monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
        monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access")
        monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret")

        opened_clients: list[_FakeAsyncKMSClient] = []
        session_kwargs: list[dict[str, Any]] = []

        class _FakeClientCtx:
            def __init__(self, client: _FakeAsyncKMSClient) -> None:
                self._client = client

            async def __aenter__(self) -> _FakeAsyncKMSClient:
                opened_clients.append(self._client)
                return self._client

            async def __aexit__(self, *exc: Any) -> None:
                pass

        class _FakeAioSession:
            def __init__(self, **kwargs: Any) -> None:
                session_kwargs.append(kwargs)

            def client(self, service: str, **client_kwargs: Any) -> _FakeClientCtx:
                assert service == "kms"
                return _FakeClientCtx(_FakeAsyncKMSClient(plaintext_data_key=b"\x00" * 32))

        monkeypatch.setattr(
            "pydantic_encryption.adapters.encryption.aws.aioboto3.Session", _FakeAioSession
        )

        await AWSAdapter.async_encrypt(b"payload")

        assert len(opened_clients) == 1
        assert session_kwargs[0]["region_name"] == "us-east-1"
        assert AWSAdapter._async_client is opened_clients[0]
        assert AWSAdapter._async_loop is asyncio.get_running_loop()

        await AWSAdapter.async_encrypt(b"payload-2")

        assert len(opened_clients) == 1

        _reset_adapter_state()

    @pytest.mark.asyncio
    async def test_async_kms_coalesces_concurrent_first_callers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that concurrent first-time async_encrypt calls open the aioboto3 client exactly once."""

        _reset_adapter_state()

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
        monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
        monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access")
        monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret")

        opened_clients: list[_FakeAsyncKMSClient] = []

        class _FakeClientCtx:
            def __init__(self, client: _FakeAsyncKMSClient) -> None:
                self._client = client

            async def __aenter__(self) -> _FakeAsyncKMSClient:
                await asyncio.sleep(0)
                opened_clients.append(self._client)
                return self._client

            async def __aexit__(self, *exc: Any) -> None:
                pass

        class _FakeAioSession:
            def __init__(self, **kwargs: Any) -> None:
                pass

            def client(self, service: str, **client_kwargs: Any) -> _FakeClientCtx:
                return _FakeClientCtx(_FakeAsyncKMSClient(plaintext_data_key=b"\x00" * 32))

        monkeypatch.setattr(
            "pydantic_encryption.adapters.encryption.aws.aioboto3.Session", _FakeAioSession
        )

        await asyncio.gather(
            AWSAdapter.async_encrypt(b"a"),
            AWSAdapter.async_encrypt(b"b"),
            AWSAdapter.async_encrypt(b"c"),
        )

        assert len(opened_clients) == 1

        _reset_adapter_state()

    @pytest.mark.asyncio
    async def test_aclose_async_kms_exits_the_context_manager(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that aclose_async_kms() drives __aexit__ on the cached aioboto3 client context."""

        _reset_adapter_state()

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
        monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
        monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
        monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access")
        monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret")

        exit_calls: list[tuple[Any, ...]] = []

        class _FakeClientCtx:
            def __init__(self, client: _FakeAsyncKMSClient) -> None:
                self._client = client

            async def __aenter__(self) -> _FakeAsyncKMSClient:
                return self._client

            async def __aexit__(self, *exc: Any) -> None:
                exit_calls.append(exc)

        class _FakeAioSession:
            def __init__(self, **kwargs: Any) -> None:
                pass

            def client(self, service: str, **client_kwargs: Any) -> _FakeClientCtx:
                return _FakeClientCtx(_FakeAsyncKMSClient(plaintext_data_key=b"\x00" * 32))

        monkeypatch.setattr(
            "pydantic_encryption.adapters.encryption.aws.aioboto3.Session", _FakeAioSession
        )

        await AWSAdapter.async_encrypt(b"warm")

        assert AWSAdapter._async_client is not None

        await AWSAdapter.aclose_async_kms()

        assert exit_calls == [(None, None, None)]
        assert AWSAdapter._async_client is None
        assert AWSAdapter._async_client_ctx is None
        assert AWSAdapter._async_loop is None

        await AWSAdapter.aclose_async_kms()

        assert exit_calls == [(None, None, None)]

        _reset_adapter_state()
