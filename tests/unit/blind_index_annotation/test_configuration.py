from typing import Annotated

import pytest

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod
from pydantic_encryption.config import settings


class TestBlindIndexAnnotationConfiguration:
    """Test what a BlindIndex annotation refuses when declared or applied."""

    def test_missing_secret_key_refused(self, monkeypatch: pytest.MonkeyPatch):
        """Test that indexing without BLIND_INDEX_SECRET_KEY raises a clear error."""

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        class _Model(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            _Model(email_index="sample@example.test")

    def test_uninstantiated_annotation_refused(self):
        """Test that annotating with the BlindIndex class instead of an instance raises a clear error."""

        class _Model(BaseModel):
            email_index: Annotated[str | bytes, BlindIndex]

        with pytest.raises(TypeError, match="must be annotated with a BlindIndex"):
            _Model(email_index="sample@example.test")

    @pytest.mark.parametrize(
        ("flags", "message"),
        [
            (
                {"strip_non_characters": True, "strip_non_digits": True},
                "strip_non_characters and strip_non_digits cannot both be True",
            ),
            (
                {"normalize_to_lowercase": True, "normalize_to_uppercase": True},
                "normalize_to_lowercase and normalize_to_uppercase cannot both be True",
            ),
        ],
        ids=["strip", "case"],
    )
    def test_conflicting_flags_refused(self, flags: dict[str, bool], message: str):
        """Test that two normalization flags that contradict each other are refused."""

        with pytest.raises(ValueError, match=message):
            BlindIndex(BlindIndexMethod.HMAC_SHA256, **flags)
