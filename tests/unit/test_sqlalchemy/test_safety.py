import pytest

from pydantic_encryption import is_encrypted
from pydantic_encryption.types import (
    BlindIndexValue,
    EncryptedValue,
    EncryptedValueAccessError,
    HashedValue,
)


class TestEncryptedValueRepr:
    """Test that repr() does not leak raw ciphertext bytes."""

    def test_repr_is_safe_marker(self):
        value = EncryptedValue(b"\x80\x04\x95\x00\x00super-secret-ciphertext-bytes")

        rendered = repr(value)

        assert rendered == f"<EncryptedValue: {len(value)} bytes>"
        assert "super-secret-ciphertext-bytes" not in rendered

    def test_repr_reports_length(self):
        value = EncryptedValue(b"hello")

        assert repr(value) == "<EncryptedValue: 5 bytes>"

    def test_hashed_value_repr_is_safe_marker(self):
        value = HashedValue(b"$argon2id$v=19$m=65536,t=3,p=4$some-salt$some-hash")

        assert repr(value).startswith("<HashedValue:")
        assert "argon2" not in repr(value)

    def test_blind_index_value_repr_is_safe_marker(self):
        value = BlindIndexValue(b"some-hmac-bytes")

        assert repr(value).startswith("<BlindIndexValue:")


class TestEncryptedValueStrRaises:
    """Test that coercing an encrypted value to a string raises EncryptedValueAccessError."""

    def test_str_raises(self):
        value = EncryptedValue(b"secret")

        with pytest.raises(EncryptedValueAccessError):
            str(value)

    def test_f_string_raises(self):
        value = EncryptedValue(b"secret")

        with pytest.raises(EncryptedValueAccessError):
            f"{value}"

    def test_percent_format_raises(self):
        value = EncryptedValue(b"secret")

        with pytest.raises(EncryptedValueAccessError):
            "%s" % value

    def test_error_message_points_at_decrypt_path(self):
        value = EncryptedValue(b"secret")

        with pytest.raises(EncryptedValueAccessError) as exc_info:
            str(value)

        message = str(exc_info.value)
        assert "decrypt" in message.lower()
        assert "bytes(" in message

    def test_bytes_coercion_still_works(self):
        value = EncryptedValue(b"secret-ciphertext")

        assert bytes(value) == b"secret-ciphertext"

    def test_equality_still_works(self):
        a = EncryptedValue(b"x")
        b = EncryptedValue(b"x")
        c = EncryptedValue(b"y")

        assert a == b
        assert a != c
        assert a == b"x"

    def test_hash_still_works(self):
        value = EncryptedValue(b"x")

        assert hash(value) == hash(b"x")


class TestHashedAndBlindIndexStrDoNotRaise:
    """Test that HashedValue and BlindIndexValue keep bytes-like str() (only EncryptedValue raises)."""

    def test_hashed_value_str_does_not_raise(self):
        value = HashedValue(b"hash")

        str(value)

    def test_blind_index_value_str_does_not_raise(self):
        value = BlindIndexValue(b"index")

        str(value)


class TestIsEncryptedHelper:
    """Test the public is_encrypted guard for boundary code."""

    def test_encrypted_value_returns_true(self):
        assert is_encrypted(EncryptedValue(b"x")) is True

    def test_plain_bytes_returns_false(self):
        assert is_encrypted(b"x") is False

    def test_str_returns_false(self):
        assert is_encrypted("x") is False

    def test_none_returns_false(self):
        assert is_encrypted(None) is False

    def test_hashed_value_returns_false(self):
        assert is_encrypted(HashedValue(b"x")) is False

    def test_blind_index_value_returns_false(self):
        assert is_encrypted(BlindIndexValue(b"x")) is False
