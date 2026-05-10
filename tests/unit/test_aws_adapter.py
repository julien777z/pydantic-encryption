from collections.abc import Iterator

import pytest

pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import (
    CIPHERTEXT_MAGIC,
    CIPHERTEXT_VERSION,
    HEADER_LENGTH,
    NONCE_LENGTH,
    AWSAdapter,
)
from pydantic_encryption.types import EncryptedValue


def _reset_adapter_state() -> None:
    """Clear lazily-initialized state so each test starts fresh."""

    AWSAdapter._kms_client = None
    AWSAdapter._data_key_cache = None


class _FakeKMSClient:
    """Stand-in boto3 KMS client that records calls and returns deterministic blobs."""

    def __init__(self, plaintext_data_key: bytes) -> None:
        self.plaintext_data_key = plaintext_data_key
        self.generate_calls: list[dict] = []
        self.decrypt_calls: list[dict] = []
        self.next_wrapped_key: bytes = b"wrapped-key"

    def generate_data_key(self, **kwargs):
        """Return a fixed plaintext key and a unique wrapped key per call."""

        self.generate_calls.append(kwargs)

        return {
            "Plaintext": self.plaintext_data_key,
            "CiphertextBlob": self.next_wrapped_key,
        }

    def decrypt(self, **kwargs):
        """Return the fixed plaintext key for any wrapped key."""

        self.decrypt_calls.append(kwargs)

        return {"Plaintext": self.plaintext_data_key}


@pytest.fixture
def fake_kms(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeKMSClient]:
    """Install a fake KMS client and seed AWS settings for the test process."""

    _reset_adapter_state()

    from pydantic_encryption.config import settings

    monkeypatch.setattr(settings, "AWS_KMS_KEY_ARN", "arn:aws:kms:us-east-1:000:key/test")
    monkeypatch.setattr(settings, "AWS_KMS_ENCRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", None)
    monkeypatch.setattr(settings, "AWS_KMS_REGION", "us-east-1")
    monkeypatch.setattr(settings, "AWS_KMS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setattr(settings, "AWS_KMS_SECRET_ACCESS_KEY", "test-secret-key")
    monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_REUSE_MAX_USES", 1)
    monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_REUSE_MAX_AGE_SECONDS", 300)
    monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_DECRYPT_CACHE_CAPACITY", 0)

    client = _FakeKMSClient(plaintext_data_key=b"\x00" * 32)
    AWSAdapter._kms_client = client

    yield client

    _reset_adapter_state()


class TestAWSAdapterEncrypt:
    """Test that encrypt() wraps a fresh data key under KMS and seals the plaintext with AES-GCM."""

    def test_encrypt_returns_encrypted_value_with_known_header(self, fake_kms: _FakeKMSClient) -> None:
        """Test that encrypt() emits an EncryptedValue starting with the format magic + version."""

        result = AWSAdapter.encrypt(b"plaintext-payload")

        assert isinstance(result, EncryptedValue)

        blob = bytes(result)
        assert blob[0] == CIPHERTEXT_MAGIC
        assert blob[1] == CIPHERTEXT_VERSION

    def test_encrypt_calls_generate_data_key_once_per_call(self, fake_kms: _FakeKMSClient) -> None:
        """Test that every encrypt() call requests a fresh KMS data key."""

        AWSAdapter.encrypt(b"payload-1")
        AWSAdapter.encrypt(b"payload-2")

        assert len(fake_kms.generate_calls) == 2
        for call in fake_kms.generate_calls:
            assert call["KeySpec"] == "AES_256"

    def test_encrypt_encodes_str_input(self, fake_kms: _FakeKMSClient) -> None:
        """Test that encrypt() encodes a str plaintext to utf-8 before sealing."""

        AWSAdapter.encrypt("plain-str")

        assert len(fake_kms.generate_calls) == 1

    def test_encrypt_passthrough_for_already_encrypted_value(self, fake_kms: _FakeKMSClient) -> None:
        """Test that encrypt() returns an existing EncryptedValue unchanged without invoking KMS."""

        already_encrypted = EncryptedValue(b"already-sealed")

        result = AWSAdapter.encrypt(already_encrypted)

        assert result is already_encrypted
        assert fake_kms.generate_calls == []


class TestAWSAdapterDecrypt:
    """Test that decrypt() unwraps the data key via KMS and AES-GCM-decrypts the payload."""

    def test_encrypt_then_decrypt_round_trips(self, fake_kms: _FakeKMSClient) -> None:
        """Test that decrypt(encrypt(x)) returns x as a str."""

        sealed = AWSAdapter.encrypt("hello world")

        result = AWSAdapter.decrypt(sealed)

        assert result == "hello world"
        assert len(fake_kms.decrypt_calls) == 1

    def test_decrypt_each_call_invokes_kms(self, fake_kms: _FakeKMSClient) -> None:
        """Test that every decrypt() call routes through the KMS client (no plaintext cache)."""

        sealed_one = AWSAdapter.encrypt("first")
        fake_kms.next_wrapped_key = b"wrapped-key-2"
        sealed_two = AWSAdapter.encrypt("second")

        AWSAdapter.decrypt(sealed_one)
        AWSAdapter.decrypt(sealed_one)
        AWSAdapter.decrypt(sealed_two)

        assert len(fake_kms.decrypt_calls) == 3

    def test_decrypt_rejects_unrecognized_format(self, fake_kms: _FakeKMSClient) -> None:
        """Test that decrypt() raises ValueError when the magic byte does not match."""

        bogus = b"\x01" + b"\x00" * 32

        with pytest.raises(ValueError, match="Unrecognized ciphertext format"):
            AWSAdapter.decrypt(bogus)

    def test_decrypt_rejects_unsupported_version(self, fake_kms: _FakeKMSClient) -> None:
        """Test that decrypt() raises ValueError when the version byte is not supported."""

        unsupported = bytes([CIPHERTEXT_MAGIC, 0x99]) + b"\x00" * (HEADER_LENGTH + NONCE_LENGTH)

        with pytest.raises(ValueError, match="Unsupported"):
            AWSAdapter.decrypt(unsupported)

    def test_decrypt_passes_decrypt_arn_to_kms_when_configured(
        self,
        fake_kms: _FakeKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that decrypt() includes the configured KeyId when AWS_KMS_DECRYPT_KEY_ARN is set."""

        from pydantic_encryption.config import settings

        sealed = AWSAdapter.encrypt("payload")
        monkeypatch.setattr(settings, "AWS_KMS_DECRYPT_KEY_ARN", "arn:aws:kms:us-east-1:000:key/dec")

        AWSAdapter.decrypt(sealed)

        assert fake_kms.decrypt_calls[-1]["KeyId"] == "arn:aws:kms:us-east-1:000:key/dec"


class TestAWSAdapterDataKeyCache:
    """Test that the data-key cache amortizes KMS calls across many cells."""

    def test_encrypt_reuses_data_key_within_max_uses(
        self,
        fake_kms: _FakeKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that encrypt() reuses one data key for ``max_uses`` calls before regenerating."""

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_REUSE_MAX_USES", 5)
        AWSAdapter._data_key_cache = None

        for _ in range(5):
            AWSAdapter.encrypt(b"payload")

        assert len(fake_kms.generate_calls) == 1

        AWSAdapter.encrypt(b"payload")

        assert len(fake_kms.generate_calls) == 2

    def test_decrypt_caches_unwrapped_data_key(
        self,
        fake_kms: _FakeKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that decrypt() reuses an unwrapped data key when the wrapped blob repeats."""

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_REUSE_MAX_USES", 100)
        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_DECRYPT_CACHE_CAPACITY", 16)
        AWSAdapter._data_key_cache = None

        sealed_one = AWSAdapter.encrypt("first")
        sealed_two = AWSAdapter.encrypt("second")

        AWSAdapter.decrypt(sealed_one)
        AWSAdapter.decrypt(sealed_two)

        assert len(fake_kms.decrypt_calls) == 1

    def test_decrypt_cache_disabled_with_zero_capacity(
        self,
        fake_kms: _FakeKMSClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Test that capacity=0 routes every decrypt() through KMS even on repeats."""

        from pydantic_encryption.config import settings

        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_REUSE_MAX_USES", 100)
        monkeypatch.setattr(settings, "AWS_KMS_DATA_KEY_DECRYPT_CACHE_CAPACITY", 0)
        AWSAdapter._data_key_cache = None

        sealed = AWSAdapter.encrypt("only")

        AWSAdapter.decrypt(sealed)
        AWSAdapter.decrypt(sealed)
        AWSAdapter.decrypt(sealed)

        assert len(fake_kms.decrypt_calls) == 3
