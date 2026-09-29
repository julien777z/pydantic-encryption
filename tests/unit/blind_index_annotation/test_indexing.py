from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod
from pydantic_encryption.types import BlindIndexValue


class TestBlindIndexAnnotation:
    """Test that a field annotated with BlindIndex holds its blind index once validated."""

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_field_indexed(self, method: BlindIndexMethod):
        """Test that the field holds a 32-byte BlindIndexValue."""

        class _Model(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(method)]

        model = _Model(email_index="sample@example.test")

        assert isinstance(model.email_index, BlindIndexValue)
        assert len(model.email_index) == 32

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_index_is_deterministic(self, method: BlindIndexMethod):
        """Test that one value indexes the same way twice and differently from another value."""

        class _Model(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(method)]

        first = _Model(email_index="first@example.test").email_index

        assert _Model(email_index="first@example.test").email_index == first
        assert _Model(email_index="second@example.test").email_index != first

    def test_bytes_indexed_as_text(self):
        """Test that UTF-8 bytes index the same as the text they encode."""

        class _Model(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        assert (
            _Model(email_index=b"sample@example.test").email_index
            == _Model(email_index="sample@example.test").email_index
        )

    def test_methods_differ(self):
        """Test that the two methods index one value differently."""

        class _HMACModel(BaseModel):
            index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        class _Argon2Model(BaseModel):
            index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.ARGON2)]

        assert (
            _HMACModel(index="sample@example.test").index != _Argon2Model(index="sample@example.test").index
        )

    def test_indexed_value_not_reindexed(self):
        """Test that a value already holding a blind index is kept as it is."""

        class _Model(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        first_index = _Model(email_index="sample@example.test").email_index

        assert _Model(email_index=first_index).email_index == first_index

    def test_none_stays_none(self):
        """Test that an optional field left None is not indexed."""

        class _Model(BaseModel):
            email_index: Annotated[str | bytes | None, BlindIndex(BlindIndexMethod.HMAC_SHA256)] = None

        assert _Model().email_index is None
