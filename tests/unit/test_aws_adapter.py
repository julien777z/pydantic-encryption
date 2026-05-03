from unittest.mock import MagicMock

import pytest

pytest.importorskip("aws_encryption_sdk")
pytest.importorskip("boto3")

from pydantic_encryption.adapters.encryption.aws import AWSAdapter
from pydantic_encryption.types import EncryptedValue


def _reset_adapter_state() -> None:
    """Clear every class-level client AWSAdapter lazily builds so each test starts fresh."""

    AWSAdapter._kms_client = None
    AWSAdapter._encryption_client = None
    AWSAdapter._mat_prov = None
    AWSAdapter._encrypt_keyring = None
    AWSAdapter._decrypt_keyring = None


class TestAWSAdapterDecrypt:
    """Test that decrypt() routes ciphertext through the AWS Encryption SDK and returns the plaintext."""

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

    def test_decrypt_returns_plaintext_string(self) -> None:
        """Test that decrypt() decodes the SDK's bytes plaintext into a str."""

        client = self._install_fake_clients(b"hello")

        result = AWSAdapter.decrypt(b"ciphertext-1")

        assert result == "hello"
        client.decrypt.assert_called_once()

    def test_decrypt_each_call_invokes_kms(self) -> None:
        """Test that every decrypt() call routes through the encryption client (no cache)."""

        client = self._install_fake_clients(b"hello")

        AWSAdapter.decrypt(b"ciphertext-1")
        AWSAdapter.decrypt(b"ciphertext-1")
        AWSAdapter.decrypt(b"ciphertext-2")

        assert client.decrypt.call_count == 3

    def test_decrypt_accepts_str_input(self) -> None:
        """Test that decrypt() encodes a str ciphertext to utf-8 bytes before dispatch."""

        client = self._install_fake_clients(b"value")

        result = AWSAdapter.decrypt("ciphertext-str")

        assert result == "value"
        call_kwargs = client.decrypt.call_args.kwargs
        assert call_kwargs["source"] == b"ciphertext-str"


class TestAWSAdapterEncrypt:
    """Test that encrypt() routes plaintext through the AWS Encryption SDK and wraps the result."""

    def setup_method(self) -> None:
        _reset_adapter_state()

    def teardown_method(self) -> None:
        _reset_adapter_state()

    def _install_fake_clients(self, ciphertext: bytes = b"sealed") -> MagicMock:
        """Replace lazy-initialized AWS clients with mocks so encrypt() is pure logic."""

        fake_enc_client = MagicMock()
        fake_enc_client.encrypt.return_value = (ciphertext, None)
        AWSAdapter._kms_client = MagicMock(name="kms-client")
        AWSAdapter._encryption_client = fake_enc_client
        AWSAdapter._mat_prov = MagicMock(name="mat-prov")
        AWSAdapter._encrypt_keyring = MagicMock(name="encrypt-keyring")
        return fake_enc_client

    def test_encrypt_wraps_ciphertext_in_encrypted_value(self) -> None:
        """Test that encrypt() returns the SDK ciphertext as an EncryptedValue."""

        self._install_fake_clients(b"sealed")

        result = AWSAdapter.encrypt(b"plaintext")

        assert isinstance(result, EncryptedValue)
        assert bytes(result) == b"sealed"

    def test_encrypt_encodes_str_input(self) -> None:
        """Test that encrypt() encodes a str plaintext to utf-8 bytes before dispatch."""

        client = self._install_fake_clients(b"sealed")

        AWSAdapter.encrypt("plain-str")

        call_kwargs = client.encrypt.call_args.kwargs
        assert call_kwargs["source"] == b"plain-str"

    def test_encrypt_passthrough_for_already_encrypted_value(self) -> None:
        """Test that encrypt() returns an existing EncryptedValue unchanged without invoking KMS."""

        client = self._install_fake_clients(b"sealed")

        already_encrypted = EncryptedValue(b"already-sealed")
        result = AWSAdapter.encrypt(already_encrypted)

        assert result is already_encrypted
        client.encrypt.assert_not_called()
