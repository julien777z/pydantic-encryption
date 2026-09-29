import pytest
from sqlalchemy.engine import Dialect

from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy.blind_index import SQLAlchemyBlindIndexValue
from pydantic_encryption.types import BlindIndexMethod, BlindIndexValue


class TestBlindIndexBind:
    """Test the blind index a column computes for the values bound to it."""

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_none_binds_none(self, method: BlindIndexMethod, sqlite_dialect: Dialect):
        """Test that binding None stores None."""

        assert SQLAlchemyBlindIndexValue(method).process_bind_param(None, sqlite_dialect) is None

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    @pytest.mark.parametrize("value", ["sample@example.test", b"sample@example.test"], ids=["str", "bytes"])
    def test_index_is_32_bytes(self, method: BlindIndexMethod, value: str | bytes, sqlite_dialect: Dialect):
        """Test that a text or bytes value binds as a 32-byte index."""

        result = SQLAlchemyBlindIndexValue(method).process_bind_param(value, sqlite_dialect)

        assert isinstance(result, bytes)
        assert len(result) == 32

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_index_is_deterministic(self, method: BlindIndexMethod, sqlite_dialect: Dialect):
        """Test that the same value always binds to the same index."""

        column_type = SQLAlchemyBlindIndexValue(method)

        assert column_type.process_bind_param(
            "sample@example.test", sqlite_dialect
        ) == column_type.process_bind_param("sample@example.test", sqlite_dialect)

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_str_and_bytes_share_index(self, method: BlindIndexMethod, sqlite_dialect: Dialect):
        """Test that a string and its UTF-8 bytes bind to the same index."""

        column_type = SQLAlchemyBlindIndexValue(method)

        assert column_type.process_bind_param("hello", sqlite_dialect) == column_type.process_bind_param(
            b"hello", sqlite_dialect
        )

    @pytest.mark.parametrize("method", list(BlindIndexMethod))
    def test_different_values_differ(self, method: BlindIndexMethod, sqlite_dialect: Dialect):
        """Test that different values bind to different indexes."""

        column_type = SQLAlchemyBlindIndexValue(method)

        assert column_type.process_bind_param(
            "first@example.test", sqlite_dialect
        ) != column_type.process_bind_param("second@example.test", sqlite_dialect)

    def test_precomputed_index_passes_through(self, sqlite_dialect: Dialect):
        """Test that binding an existing blind index stores it unchanged."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)
        index = column_type.process_bind_param("sample@example.test", sqlite_dialect)

        assert index is not None
        assert column_type.process_bind_param(BlindIndexValue(index), sqlite_dialect) == index

    def test_methods_differ(self, sqlite_dialect: Dialect):
        """Test that the two methods bind one value to different indexes."""

        hmac_index = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_bind_param(
            "sample@example.test", sqlite_dialect
        )
        argon2_index = SQLAlchemyBlindIndexValue(BlindIndexMethod.ARGON2).process_bind_param(
            "sample@example.test", sqlite_dialect
        )

        assert hmac_index != argon2_index

    def test_keys_differ(self, monkeypatch: pytest.MonkeyPatch, sqlite_dialect: Dialect):
        """Test that one value binds to different indexes under different secret keys."""

        column_type = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256)

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "key-one")
        first = column_type.process_bind_param("sample@example.test", sqlite_dialect)

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", "key-two")
        second = column_type.process_bind_param("sample@example.test", sqlite_dialect)

        assert first != second

    def test_missing_secret_key_refused(self, monkeypatch: pytest.MonkeyPatch, sqlite_dialect: Dialect):
        """Test that binding without BLIND_INDEX_SECRET_KEY raises."""

        monkeypatch.setattr(settings, "BLIND_INDEX_SECRET_KEY", None)

        with pytest.raises(ValueError, match="BLIND_INDEX_SECRET_KEY must be set"):
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_bind_param(
                "sample", sqlite_dialect
            )

    def test_none_result_reads_none(self, sqlite_dialect: Dialect):
        """Test that a stored None reads back as None."""

        assert (
            SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_result_value(None, sqlite_dialect)
            is None
        )

    def test_result_reads_as_blind_index(self, sqlite_dialect: Dialect):
        """Test that a stored index reads back as a BlindIndexValue of the same bytes."""

        stored = b"\x01\x02\x03\x04" * 8
        result = SQLAlchemyBlindIndexValue(BlindIndexMethod.HMAC_SHA256).process_result_value(
            stored, sqlite_dialect
        )

        assert isinstance(result, BlindIndexValue)
        assert result == stored
