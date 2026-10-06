import pytest

from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod


class TestBlindIndexConfiguration:
    """Test what a blind index column type accepts and records when declared."""

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
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256, **flags)

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_method_recorded(self, method: BlindIndexMethod):
        """Test that the column type records the method it was declared with."""

        assert SQLAlchemyBlindIndexValue(method).method == method

    def test_python_type_is_bytes(self):
        """Test that the column type reports bytes as its Python type."""

        assert SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).python_type is bytes
