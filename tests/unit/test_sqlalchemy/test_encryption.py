import base64
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from uuid import UUID

import pytest
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from pydantic_encryption.adapters.encryption.fernet import FernetAdapter
from pydantic_encryption.config import settings
from pydantic_encryption.context import derive_column_context
from pydantic_encryption.integrations.sqlalchemy.encryption import (
    SQLAlchemyEncryptedValue,
    SQLAlchemyPGEncryptedArray,
)
from pydantic_encryption.serialization import (
    TypePrefix,
    decode_value,
    encode_value,
)


class TestEncodeValue:
    """Test ``encode_value`` serialization."""

    def test_serialize_str(self):
        result = encode_value("hello world")
        assert result == f"v1:{TypePrefix.STR}:hello world"

    def test_serialize_str_with_colon(self):
        result = encode_value("hello:world")
        assert result == f"v1:{TypePrefix.STR}:hello:world"

    def test_serialize_bytes(self):
        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        result = encode_value(test_bytes)
        expected_b64 = base64.b64encode(test_bytes).decode("ascii")
        assert result == f"v1:{TypePrefix.BYTES}:{expected_b64}"

    def test_serialize_bytes_empty(self):
        result = encode_value(b"")
        assert result == f"v1:{TypePrefix.BYTES}:"

    def test_serialize_int(self):
        result = encode_value(42)
        assert result == f"v1:{TypePrefix.INT}:42"

    def test_serialize_int_negative(self):
        result = encode_value(-123)
        assert result == f"v1:{TypePrefix.INT}:-123"

    def test_serialize_bool_true(self):
        result = encode_value(True)
        assert result == f"v1:{TypePrefix.BOOL}:true"

    def test_serialize_bool_false(self):
        result = encode_value(False)
        assert result == f"v1:{TypePrefix.BOOL}:false"

    def test_serialize_date(self):
        result = encode_value(date(2025, 1, 21))
        assert result == f"v1:{TypePrefix.DATE}:2025-01-21"

    def test_serialize_datetime(self):
        result = encode_value(datetime(2025, 1, 21, 14, 30, 45))
        assert result == f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45"

    def test_serialize_datetime_with_timezone(self):
        result = encode_value(datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc))
        assert result == f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00"

    def test_serialize_time(self):
        result = encode_value(time(14, 30, 45))
        assert result == f"v1:{TypePrefix.TIME}:14:30:45"

    def test_serialize_time_with_microseconds(self):
        result = encode_value(time(14, 30, 45, 123456))
        assert result == f"v1:{TypePrefix.TIME}:14:30:45.123456"

    def test_serialize_time_with_timezone(self):
        result = encode_value(time(14, 30, 45, tzinfo=timezone.utc))
        assert result == f"v1:{TypePrefix.TIME}:14:30:45+00:00"

    def test_serialize_timedelta(self):
        td = timedelta(days=1, hours=2, minutes=30, seconds=45)
        result = encode_value(td)
        assert result == f"v1:{TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_timedelta_negative(self):
        td = timedelta(days=-1, hours=-2)
        result = encode_value(td)
        assert result == f"v1:{TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_timedelta_fractional(self):
        td = timedelta(seconds=1.5)
        result = encode_value(td)
        assert result == f"v1:{TypePrefix.TIMEDELTA}:{td.days},{td.seconds},{td.microseconds}"

    def test_serialize_float(self):
        result = encode_value(3.14159)
        assert result == f"v1:{TypePrefix.FLOAT}:3.14159"

    def test_serialize_float_negative(self):
        result = encode_value(-2.5)
        assert result == f"v1:{TypePrefix.FLOAT}:-2.5"

    def test_serialize_float_scientific(self):
        result = encode_value(1e-10)
        assert result == f"v1:{TypePrefix.FLOAT}:1e-10"

    def test_serialize_decimal(self):
        result = encode_value(Decimal("123.456789"))
        assert result == f"v1:{TypePrefix.DECIMAL}:123.456789"

    def test_serialize_decimal_high_precision(self):
        result = encode_value(Decimal("0.123456789012345678901234567890"))
        assert result == f"v1:{TypePrefix.DECIMAL}:0.123456789012345678901234567890"

    def test_serialize_decimal_negative(self):
        result = encode_value(Decimal("-999.99"))
        assert result == f"v1:{TypePrefix.DECIMAL}:-999.99"

    def test_serialize_uuid(self):
        result = encode_value(UUID("12345678-1234-5678-1234-567812345678"))
        assert result == f"v1:{TypePrefix.UUID}:12345678-1234-5678-1234-567812345678"


class TestDecodeValue:
    """Test ``decode_value`` deserialization."""

    def test_deserialize_str(self):
        result = decode_value(f"v1:{TypePrefix.STR}:hello world")
        assert result == "hello world"
        assert isinstance(result, str)

    def test_deserialize_str_with_colon(self):
        result = decode_value(f"v1:{TypePrefix.STR}:hello:world")
        assert result == "hello:world"

    def test_deserialize_bytes(self):
        test_bytes = b"\x00\x01\x02\x03binary\xff\xfe"
        encoded = base64.b64encode(test_bytes).decode("ascii")
        result = decode_value(f"v1:{TypePrefix.BYTES}:{encoded}")
        assert result == test_bytes
        assert isinstance(result, bytes)

    def test_deserialize_bytes_empty(self):
        result = decode_value(f"v1:{TypePrefix.BYTES}:")
        assert result == b""
        assert isinstance(result, bytes)

    def test_deserialize_int(self):
        result = decode_value(f"v1:{TypePrefix.INT}:42")
        assert result == 42
        assert isinstance(result, int)

    def test_deserialize_int_negative(self):
        result = decode_value(f"v1:{TypePrefix.INT}:-123")
        assert result == -123

    def test_deserialize_bool_true(self):
        result = decode_value(f"v1:{TypePrefix.BOOL}:true")
        assert result is True
        assert isinstance(result, bool)

    def test_deserialize_bool_false(self):
        result = decode_value(f"v1:{TypePrefix.BOOL}:false")
        assert result is False
        assert isinstance(result, bool)

    def test_deserialize_date(self):
        result = decode_value(f"v1:{TypePrefix.DATE}:2025-01-21")
        assert result == date(2025, 1, 21)
        assert isinstance(result, date)
        assert not isinstance(result, datetime)

    def test_deserialize_datetime(self):
        result = decode_value(f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45")
        assert result == datetime(2025, 1, 21, 14, 30, 45)
        assert isinstance(result, datetime)

    def test_deserialize_datetime_with_timezone(self):
        result = decode_value(f"v1:{TypePrefix.DATETIME}:2025-01-21T14:30:45+00:00")
        assert result == datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_time(self):
        result = decode_value(f"v1:{TypePrefix.TIME}:14:30:45")
        assert result == time(14, 30, 45)
        assert isinstance(result, time)

    def test_deserialize_time_with_microseconds(self):
        result = decode_value(f"v1:{TypePrefix.TIME}:14:30:45.123456")
        assert result == time(14, 30, 45, 123456)

    def test_deserialize_time_with_timezone(self):
        result = decode_value(f"v1:{TypePrefix.TIME}:14:30:45+00:00")
        assert result == time(14, 30, 45, tzinfo=timezone.utc)
        assert result.tzinfo is not None

    def test_deserialize_timedelta(self):
        result = decode_value(f"v1:{TypePrefix.TIMEDELTA}:1,9045,0")
        assert result == timedelta(days=1, hours=2, minutes=30, seconds=45)
        assert isinstance(result, timedelta)

    def test_deserialize_timedelta_negative(self):
        result = decode_value(f"v1:{TypePrefix.TIMEDELTA}:-2,79200,0")
        assert result == timedelta(days=-1, hours=-2)

    def test_deserialize_timedelta_fractional(self):
        result = decode_value(f"v1:{TypePrefix.TIMEDELTA}:0,1,500000")
        assert result == timedelta(seconds=1.5)

    def test_deserialize_float(self):
        result = decode_value(f"v1:{TypePrefix.FLOAT}:3.14159")
        assert result == 3.14159
        assert isinstance(result, float)

    def test_deserialize_float_negative(self):
        result = decode_value(f"v1:{TypePrefix.FLOAT}:-2.5")
        assert result == -2.5

    def test_deserialize_float_scientific(self):
        result = decode_value(f"v1:{TypePrefix.FLOAT}:1e-10")
        assert result == 1e-10

    def test_deserialize_decimal(self):
        result = decode_value(f"v1:{TypePrefix.DECIMAL}:123.456789")
        assert result == Decimal("123.456789")
        assert isinstance(result, Decimal)

    def test_deserialize_decimal_high_precision(self):
        result = decode_value(f"v1:{TypePrefix.DECIMAL}:0.123456789012345678901234567890")
        assert result == Decimal("0.123456789012345678901234567890")

    def test_deserialize_decimal_negative(self):
        result = decode_value(f"v1:{TypePrefix.DECIMAL}:-999.99")
        assert result == Decimal("-999.99")

    def test_deserialize_uuid(self):
        result = decode_value(f"v1:{TypePrefix.UUID}:12345678-1234-5678-1234-567812345678")
        assert result == UUID("12345678-1234-5678-1234-567812345678")
        assert isinstance(result, UUID)

    def test_deserialize_legacy_format_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("str:hello world")

    def test_deserialize_unknown_version_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("v2:str:hello world")

    def test_deserialize_no_colon_raises_error(self):
        with pytest.raises(RuntimeError, match="Unknown version"):
            decode_value("no_colon_here")


class TestRoundTrip:
    """Test round-trip ``encode_value`` / ``decode_value``."""

    def test_roundtrip_str(self):
        original = "hello world"
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_bytes(self):
        original = b"\x00\x01\x02\x03binary\xff\xfe"
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_int(self):
        original = -12345
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_bool_true(self):
        result = decode_value(encode_value(True))
        assert result is True
        assert isinstance(result, bool)

    def test_roundtrip_bool_false(self):
        result = decode_value(encode_value(False))
        assert result is False
        assert isinstance(result, bool)

    def test_roundtrip_date(self):
        original = date(2025, 1, 21)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_datetime(self):
        original = datetime(2025, 1, 21, 14, 30, 45, tzinfo=timezone.utc)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_time(self):
        original = time(14, 30, 45, 123456, tzinfo=timezone.utc)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_timedelta(self):
        original = timedelta(days=5, hours=3, minutes=30, seconds=45, microseconds=123456)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_timedelta_negative(self):
        original = timedelta(days=-10, hours=-5)
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_float(self):
        original = 3.141592653589793
        assert decode_value(encode_value(original)) == original

    def test_roundtrip_decimal(self):
        original = Decimal("123.456789012345678901234567890")
        result = decode_value(encode_value(original))
        assert result == original
        assert isinstance(result, Decimal)

    def test_roundtrip_uuid(self):
        original = UUID("12345678-1234-5678-1234-567812345678")
        result = decode_value(encode_value(original))
        assert result == original
        assert isinstance(result, UUID)


class TestEncryptionIdempotency:
    """Test that already-encrypted values are not re-encrypted."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyEncryptedValue("tests.encrypted_column.value")

    def test_encrypt_cell_already_encrypted_returns_same(self):
        encrypted = self.type_adapter.encrypt_cell("hello")
        double_encrypted = self.type_adapter.encrypt_cell(encrypted)
        assert encrypted == double_encrypted

    def test_process_bind_param_already_encrypted_returns_same(self):
        from pydantic_encryption.types import EncryptedValue

        encrypted = self.type_adapter.process_bind_param("hello", None)
        double_encrypted = self.type_adapter.process_bind_param(EncryptedValue(encrypted), None)
        assert encrypted == double_encrypted

    def test_process_literal_param_already_encrypted_returns_same(self):
        from pydantic_encryption.types import EncryptedValue

        encrypted = self.type_adapter.process_literal_param("hello", None)
        double_encrypted = self.type_adapter.process_literal_param(EncryptedValue(encrypted), None)
        assert encrypted == double_encrypted


class TestBackendResolution:
    """Test ``SQLAlchemyEncryptedValue.backend`` configuration handling."""

    def test_backend_returns_configured_adapter(self):
        """Test that backend returns the adapter configured by ENCRYPTION_METHOD."""

        assert SQLAlchemyEncryptedValue.backend() is FernetAdapter

    def test_backend_raises_when_encryption_method_unset(self, monkeypatch):
        """Test that backend raises a ValueError when ENCRYPTION_METHOD is unset."""

        monkeypatch.setattr(settings, "ENCRYPTION_METHOD", None)

        with pytest.raises(ValueError, match="ENCRYPTION_METHOD must be set"):
            SQLAlchemyEncryptedValue.backend()


class TestEncryptedValueNoneHandling:
    """Test ``SQLAlchemyEncryptedValue`` None handling and metadata."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyEncryptedValue("tests.encrypted_column.value")

    def test_encrypt_cell_none_returns_none(self):
        """Test that encrypting None returns None without invoking the backend."""

        assert self.type_adapter.encrypt_cell(None) is None

    def test_decrypt_cell_none_returns_none(self):
        """Test that decrypting None returns None without invoking the backend."""

        assert self.type_adapter.decrypt_cell(None) is None

    def test_python_type_matches_impl(self):
        """Test that python_type mirrors the LargeBinary impl type."""

        assert self.type_adapter.python_type is self.type_adapter.impl.python_type


class TestPGEncryptedArrayLiteralParam:
    """Test ``SQLAlchemyPGEncryptedArray.process_literal_param`` element encryption."""

    def setup_method(self):
        self.type_adapter = SQLAlchemyPGEncryptedArray("tests.encrypted_column.value")

    def test_literal_param_none_returns_none(self):
        """Test that a None array literal returns None."""

        assert self.type_adapter.process_literal_param(None, None) is None

    def test_literal_param_encrypts_each_element(self):
        """Test that each array element is encrypted for literal SQL expressions."""

        result = self.type_adapter.process_literal_param(["hello", "world"], None)

        assert result is not None
        assert len(result) == 2
        assert result[0] != "hello"
        assert result[1] != "world"


class ContextBase(DeclarativeBase):
    """Isolated declarative base for the context-derivation tests."""


class TaxIdMixin:
    """Mixin whose encrypted columns are inherited by more than one table."""

    tax_id: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    aliases: Mapped[list[str] | None] = mapped_column(
        SQLAlchemyPGEncryptedArray(), nullable=True, default=None
    )


class ContextUser(ContextBase, TaxIdMixin):
    """Table carrying the mixin column plus columns of its own."""

    __tablename__ = "context_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[bytes | None] = mapped_column(SQLAlchemyEncryptedValue(), nullable=True, default=None)
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)
    envelope: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue("onboarding.draft"), nullable=True, default=None
    )


class ContextContractor(ContextBase, TaxIdMixin):
    """Second table carrying the same mixin column."""

    __tablename__ = "context_contractors"

    id: Mapped[int] = mapped_column(primary_key=True)


class SecureAuditLog(ContextBase):
    """Table whose name is shared with another table in a different schema."""

    __tablename__ = "context_audit_log"
    __table_args__ = {"schema": "secure"}

    id: Mapped[int] = mapped_column(primary_key=True)
    field_value_before: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )
    tags: Mapped[list[str] | None] = mapped_column(SQLAlchemyPGEncryptedArray(), nullable=True, default=None)


class PublicAuditLog(ContextBase):
    """Same table name in a second schema, whose columns must bind separately."""

    __tablename__ = "context_audit_log"
    __table_args__ = {"schema": "vaultgig"}

    id: Mapped[int] = mapped_column(primary_key=True)
    field_value_before: Mapped[bytes | None] = mapped_column(
        SQLAlchemyEncryptedValue(), nullable=True, default=None
    )


class TestDerivedColumnContext:
    """Test that an encrypted column binds its cells to the table and column it is attached to."""

    def test_column_derives_its_table_and_column(self):
        """Test that a column with no declared context names the schema it is attached to."""

        assert ContextUser.__table__.c.email.type.context == b"context_users.email"

    def test_array_column_derives_its_table_and_column(self):
        """Test that an encrypted array derives the context every element is bound to."""

        assert ContextUser.__table__.c.tags.type.context == b"context_users.tags"
        assert ContextUser.__table__.c.tags.type._element_type.context == b"context_users.tags"

    def test_one_mixin_column_binds_each_table_separately(self):
        """Test that a column inherited from a mixin binds to each inheriting table's own name."""

        assert ContextUser.__table__.c.tax_id.type.context == b"context_users.tax_id"
        assert ContextContractor.__table__.c.tax_id.type.context == b"context_contractors.tax_id"

    def test_one_mixin_array_column_binds_each_table_separately(self):
        """Test that an inherited array column gives each table its own element type and context."""

        user_type = ContextUser.__table__.c.aliases.type
        contractor_type = ContextContractor.__table__.c.aliases.type

        assert user_type._element_type.context == b"context_users.aliases"
        assert contractor_type._element_type.context == b"context_contractors.aliases"
        assert user_type._element_type is not contractor_type._element_type

    def test_declared_context_survives_attachment(self):
        """Test that a column given a context keeps it rather than deriving one."""

        assert ContextUser.__table__.c.envelope.type.context == b"onboarding.draft"

    def test_column_in_a_schema_derives_the_qualified_table(self):
        """Test that a column in a named schema binds to the schema-qualified table."""

        column_type = SecureAuditLog.__table__.c.field_value_before.type

        assert column_type.context == b"secure.context_audit_log.field_value_before"

    def test_one_table_name_in_two_schemas_binds_separately(self):
        """Test that same-named columns in two schemas do not share one context."""

        secure_type = SecureAuditLog.__table__.c.field_value_before.type
        public_type = PublicAuditLog.__table__.c.field_value_before.type

        assert secure_type.context != public_type.context

    def test_array_elements_follow_the_column_context_exactly(self):
        """Test that an array's elements bind to the same context the array column binds to."""

        column_type = SecureAuditLog.__table__.c.tags.type

        assert column_type._element_type.context == column_type.context
        assert column_type.context == b"secure.context_audit_log.tags"

    @pytest.mark.parametrize(
        "mapped_class, schema",
        [(SecureAuditLog, "secure"), (PublicAuditLog, "vaultgig")],
        ids=["secure", "vaultgig"],
    )
    def test_derive_column_context_matches_what_a_column_derives(self, mapped_class: type, schema: str):
        """Test that the documented helper names the same context the column itself resolves."""

        column_type = mapped_class.__table__.c.field_value_before.type

        assert column_type.context == derive_column_context(
            "context_audit_log", "field_value_before", schema=schema
        )

    def test_derive_column_context_matches_an_unqualified_column(self):
        """Test that the helper names an unqualified column's context too."""

        column_type = ContextUser.__table__.c.email.type

        assert column_type.context == derive_column_context("context_users", "email")

    def test_detached_type_without_a_context_raises(self):
        """Test that a type attached to no column refuses to encrypt rather than binding nothing."""

        with pytest.raises(ValueError, match="attached to no column"):
            SQLAlchemyEncryptedValue().encrypt_cell("secret")
