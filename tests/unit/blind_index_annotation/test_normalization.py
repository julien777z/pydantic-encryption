from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod


class TestBlindIndexAnnotationNormalization:
    """Test the normalization a BlindIndex annotation applies before indexing."""

    @pytest.mark.parametrize(
        ("flags", "raw", "normalized"),
        [
            ({"normalize_to_lowercase": True}, "Hello@Example.COM", "hello@example.com"),
            ({"strip_whitespace": True}, "  first   second  ", "first second"),
            ({"strip_trailing_punctuation": True}, "first second.", "first second"),
            ({"strip_non_digits": True}, "a1 (b2) c3-d4", "1234"),
        ],
        ids=["lowercase", "strip-whitespace", "strip-trailing-punctuation", "strip-non-digits"],
    )
    def test_raw_matches_normalized(self, flags: dict[str, bool], raw: str, normalized: str):
        """Test that a raw value indexes the same as its normalized form."""

        class _Model(BaseModel):
            index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256, **flags)]

        assert _Model(index=raw).index == _Model(index=normalized).index
