from datetime import date
from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod, Encrypted, Hashed
from pydantic_encryption.types import EncryptedValue


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_string_encryption(self):
        """Test that an empty string encrypts."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="")

        assert isinstance(model.data, EncryptedValue)

    def test_whitespace_string_encryption(self):
        """Test that a whitespace-only string encrypts."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="   ")

        assert isinstance(model.data, EncryptedValue)

    def test_unicode_encryption(self):
        """Test that non-ASCII text round-trips through encryption."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "日本語 🔐 العربية"
        model = _Model(data=original)
        model.decrypt_data()

        assert model.data == original

    def test_long_string_encryption(self):
        """Test that a long string round-trips through encryption."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "x" * 10000
        model = _Model(data=original)
        model.decrypt_data()

        assert model.data == original

    @pytest.mark.parametrize(
        "marker", [Hashed, BlindIndex(BlindIndexMethod.HMAC_SHA256)], ids=["hashed", "blind_index"]
    )
    def test_non_text_digest_field_refused(self, marker: object):
        """Test that hashing or blind-indexing a field holding neither str nor bytes names the field it refused."""

        class _Model(BaseModel):
            pin: Annotated[int, marker]

        with pytest.raises(TypeError, match="'pin'"):
            _Model(pin=1234)

    def test_non_text_ciphertext_refused(self):
        """Test that decrypting a field reassigned to a non-ciphertext value names the field it refused."""

        class _Model(BaseModel):
            joined_on: Annotated[date, Encrypted]

        model = _Model(joined_on=date(1990, 5, 4))
        model.joined_on = date(1990, 5, 5)

        with pytest.raises(TypeError, match="'joined_on'"):
            model.decrypt_data()
