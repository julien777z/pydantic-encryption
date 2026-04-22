from unittest.mock import MagicMock

import pytest

pytest.importorskip("aws_encryption_sdk")
pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.config import settings


def _reset_adapter_state() -> None:
    """Clear every class-level cache AWSAdapter lazily builds so each test starts fresh."""

    AWSAdapter._kms_client = None
    AWSAdapter._encryption_client = None
    AWSAdapter._mat_prov = None
    AWSAdapter._encrypt_keyring = None
    AWSAdapter._decrypt_keyring = None
    AWSAdapter._clear_plaintext_cache()


class TestPlaintextCacheBehavior:
    """Test that repeated decrypts of the same ciphertext hit the in-process cache."""

    def setup_method(self) -> None:
        _reset_adapter_state()

    def teardown_method(self) -> None:
        _reset_adapter_state()

    def _install_fake_clients(self, plaintext: bytes = b"secret") -> MagicMock:
        """Replace the lazy-initialized AWS clients with mocks so decrypt() is pure logic."""

        fake_enc_client = MagicMock()
        fake_enc_client.decrypt.return_value = (plaintext, None)
        AWSAdapter._kms_client = MagicMock(name="kms-client")
        AWSAdapter._encryption_client = fake_enc_client
        AWSAdapter._mat_prov = MagicMock(name="mat-prov")
        AWSAdapter._decrypt_keyring = MagicMock(name="decrypt-keyring")
        return fake_enc_client

    def test_second_decrypt_of_same_ciphertext_skips_kms(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_ENABLED", True)
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_CAPACITY", 100)

        client = self._install_fake_clients(b"hello")

        first = AWSAdapter.decrypt(b"ciphertext-1")
        second = AWSAdapter.decrypt(b"ciphertext-1")

        assert first == "hello"
        assert second == "hello"
        assert client.decrypt.call_count == 1

    def test_distinct_ciphertexts_each_hit_kms_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_ENABLED", True)
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_CAPACITY", 100)

        client = self._install_fake_clients(b"hello")

        AWSAdapter.decrypt(b"ciphertext-1")
        AWSAdapter.decrypt(b"ciphertext-2")
        AWSAdapter.decrypt(b"ciphertext-1")
        AWSAdapter.decrypt(b"ciphertext-2")

        assert client.decrypt.call_count == 2

    def test_cache_disabled_always_hits_kms(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_ENABLED", False)

        client = self._install_fake_clients(b"hello")

        AWSAdapter.decrypt(b"ciphertext-1")
        AWSAdapter.decrypt(b"ciphertext-1")

        assert client.decrypt.call_count == 2

    def test_lru_eviction_respects_capacity(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_ENABLED", True)
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_CAPACITY", 2)

        client = self._install_fake_clients(b"hello")

        AWSAdapter.decrypt(b"ct-a")
        AWSAdapter.decrypt(b"ct-b")
        AWSAdapter.decrypt(b"ct-c")
        AWSAdapter.decrypt(b"ct-a")

        assert client.decrypt.call_count == 4

        AWSAdapter.decrypt(b"ct-c")
        assert client.decrypt.call_count == 4

    def test_capacity_zero_disables_cache(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_ENABLED", True)
        monkeypatch.setattr(settings, "AWS_KMS_PLAINTEXT_CACHE_CAPACITY", 0)

        client = self._install_fake_clients(b"hello")

        AWSAdapter.decrypt(b"ciphertext-1")
        AWSAdapter.decrypt(b"ciphertext-1")

        assert client.decrypt.call_count == 2
