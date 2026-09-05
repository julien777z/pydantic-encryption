import subprocess
import sys
import textwrap
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Annotated
from uuid import UUID, uuid4

import pytest
from pydantic_super_model import AnnotatedFieldInfo

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod, Encrypted, Hashed
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptedValue, EncryptionMethod, HashedValue

NO_SQLALCHEMY_SCRIPT = textwrap.dedent("""
    import sys
    from datetime import date
    from typing import Annotated


    class BlockSQLAlchemy:
        def find_module(self, name, path=None):
            return self if name == "sqlalchemy" or name.startswith("sqlalchemy.") else None

        def find_spec(self, name, path=None, target=None):
            if name == "sqlalchemy" or name.startswith("sqlalchemy."):
                raise ImportError("sqlalchemy is not installed")
            return None


    sys.meta_path.insert(0, BlockSQLAlchemy())

    from pydantic_encryption import BaseModel, Encrypted


    class Draft(BaseModel):
        dob: Annotated[date, Encrypted]


    draft = Draft(dob=date(1990, 5, 4))
    draft.decrypt_data()

    assert draft.dob == date(1990, 5, 4), draft.dob
    assert "sqlalchemy" not in sys.modules
    """)


class TestModelEncryption:
    """Test model encryption behavior."""

    def test_multiple_encrypted_fields(self):
        """Test model with multiple encrypted fields."""

        class _MultiEncrypt(BaseModel):
            field1: Annotated[str, Encrypted]
            field2: Annotated[str, Encrypted]
            field3: Annotated[str, Encrypted]

        model = _MultiEncrypt(field1="secret1", field2="secret2", field3="secret3")

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)
        assert isinstance(model.field3, EncryptedValue)

    def test_optional_encrypted_field_with_value(self):
        """Test optional encrypted field with value."""

        class _OptionalEncrypt(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = _OptionalEncrypt(secret="my secret")

        assert isinstance(model.secret, EncryptedValue)

    def test_optional_encrypted_field_none(self):
        """Test optional encrypted field with None."""

        class _OptionalEncrypt(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = _OptionalEncrypt()

        assert model.secret is None

    def test_optional_hashed_field_explicit_none(self):
        """Test optional hashed field with explicit None."""

        class _OptionalHash(BaseModel):
            password: Annotated[str, Hashed] | None

        model = _OptionalHash(password=None)

        assert model.password is None

    def test_mixed_encrypt_and_hash(self):
        """Test model with both encryption and hashing."""

        class _MixedModel(BaseModel):
            username: str
            email: Annotated[str, Encrypted]
            password: Annotated[str, Hashed]

        model = _MixedModel(username="test name", email="john@example.com", password="secret123")

        assert model.username == "test name"
        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    def test_model_inheritance(self):
        """Test encryption works with model inheritance."""

        class _BaseUser(BaseModel):
            username: str

        class _SecureUser(_BaseUser):
            password: Annotated[str, Hashed]
            secret: Annotated[str, Encrypted]

        model = _SecureUser(username="test name", password="pass123", secret="my secret")

        assert model.username == "test name"
        assert isinstance(model.password, HashedValue)
        assert isinstance(model.secret, EncryptedValue)


class TestModelDecryption:
    """Test model decryption behavior using decrypt_data()."""

    def test_decrypt_data(self):
        """Test decrypting fields in-place."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "secret data"
        model = _Model(data=original)

        assert isinstance(model.data, EncryptedValue)

        model.decrypt_data()

        assert model.data == original

    def test_decrypt_multiple_fields(self):
        """Test decrypting multiple fields."""

        class _Model(BaseModel):
            data1: Annotated[str, Encrypted]
            data2: Annotated[str, Encrypted]

        model = _Model(data1="secret1", data2="secret2")
        model.decrypt_data()

        assert model.data1 == "secret1"
        assert model.data2 == "secret2"

    def test_decrypt_data_returns_self(self):
        """Test decrypt_data returns self for chaining."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="secret")
        result = model.decrypt_data()

        assert result is model


class TestModelSerialization:
    """Test model serialization with encryption."""

    def test_model_dump_contains_encrypted(self):
        """Test model_dump contains encrypted values."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted]

        model = _EncryptModel(secret="plaintext")
        dumped = model.model_dump()

        assert dumped["secret"] != b"plaintext"
        assert isinstance(dumped["secret"], bytes)

    def test_model_dump_contains_hashed(self):
        """Test model_dump contains hashed values."""

        class _HashModel(BaseModel):
            password: Annotated[str, Hashed]

        model = _HashModel(password="plaintext")
        dumped = model.model_dump()

        assert dumped["password"] != "plaintext"
        assert b"$argon2" in dumped["password"]


class TestAnnotatedFieldLookup:
    """Test annotated field lookup behavior."""

    def test_returns_annotated_field_info_for_encrypted_fields(self):
        """Return annotated field info objects for encrypted fields."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted]

        model = _EncryptModel(secret="plaintext")
        fields = model.get_annotated_fields(Encrypted)

        assert isinstance(fields["secret"], AnnotatedFieldInfo)
        assert fields["secret"].value == model.secret
        assert fields["secret"].matched_metadata == (Encrypted,)

    def test_includes_explicit_none_values_in_annotated_field_lookup(self):
        """Include explicit None values in annotated field info results."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted] | None

        model = _EncryptModel(secret=None)

        fields = model.get_annotated_fields(Encrypted)

        assert isinstance(fields["secret"], AnnotatedFieldInfo)
        assert fields["secret"].value is None

    def test_omits_unset_default_none_values_from_annotated_field_lookup(self):
        """Omit unset default None values from annotated field info results."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = _EncryptModel()

        assert model.get_annotated_fields(Encrypted) == {}


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_string_encryption(self):
        """Test encrypting empty string."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="")

        assert isinstance(model.data, EncryptedValue)

    def test_whitespace_string_encryption(self):
        """Test encrypting whitespace string."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        model = _Model(data="   ")

        assert isinstance(model.data, EncryptedValue)

    def test_unicode_encryption(self):
        """Test encrypting unicode characters."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "日本語 🔐 العربية"
        model = _Model(data=original)
        model.decrypt_data()

        assert model.data == original

    def test_long_string_encryption(self):
        """Test encrypting long string."""

        class _Model(BaseModel):
            data: Annotated[str, Encrypted]

        original = "x" * 10000
        model = _Model(data=original)
        model.decrypt_data()

        assert model.data == original


class TestEncryptedFieldTypes:
    """Test that an encrypted field returns the type it declares."""

    @pytest.mark.parametrize(
        "annotation, value",
        [
            (str, "secret data"),
            (bytes, b"secret bytes"),
            (bool, True),
            (int, 42),
            (float, 3.5),
            (Decimal, Decimal("12.34")),
            (UUID, uuid4()),
            (date, date(1990, 5, 4)),
            (datetime, datetime(2026, 1, 2, 3, 4, 5)),
            (time, time(13, 30)),
            (timedelta, timedelta(days=2, seconds=3)),
        ],
        ids=[
            "str",
            "bytes",
            "bool",
            "int",
            "float",
            "decimal",
            "uuid",
            "date",
            "datetime",
            "time",
            "timedelta",
        ],
    )
    def test_round_trip_preserves_the_declared_type(self, annotation: type, value: object):
        """Test that every type an encrypted column accepts survives a model round trip too."""

        class _Model(BaseModel):
            data: Annotated[annotation, Encrypted]

        model = _Model(data=value)

        assert isinstance(model.data, EncryptedValue)

        model.decrypt_data()

        assert model.data == value
        assert isinstance(model.data, annotation)

    def test_model_encryption_runs_without_the_sqlalchemy_extra(self):
        """Test that encrypting a model field needs nothing from the SQLAlchemy integration."""

        environment = {
            "ENCRYPTION_METHOD": "fernet",
            "ENCRYPTION_KEY": settings.ENCRYPTION_KEY or "",
            "PATH": "/usr/bin:/bin",
        }

        result = subprocess.run(
            [sys.executable, "-c", NO_SQLALCHEMY_SCRIPT],
            capture_output=True,
            text=True,
            env=environment,
        )

        assert result.returncode == 0, result.stderr


class TestModelLevelConfig:
    """Test the encryption settings a model declares for itself."""

    def test_a_method_named_as_a_string_resolves_to_the_enum(self, fernet_key: str):
        """Test that a model naming its method as a string resolves it to the enum."""

        class StringMethodUser(BaseModel, encryption_method="fernet", encryption_key=fernet_key):
            secret: Annotated[str, Encrypted]

        assert StringMethodUser.resolve_encryption_method() is EncryptionMethod.FERNET

    def test_a_declared_key_overrides_the_environment(self, fernet_key: str):
        """Test that a model declaring its own key seals under that key rather than the configured one."""

        class DeclaredKeyUser(
            BaseModel, encryption_method=EncryptionMethod.FERNET, encryption_key=fernet_key
        ):
            secret: Annotated[str, Encrypted]

        user = DeclaredKeyUser(secret="secret data")

        assert DeclaredKeyUser.resolve_encryption_key() == fernet_key
        assert user.decrypt_data().secret == "secret data"

    def test_a_declared_blind_index_key_overrides_the_environment(self):
        """Test that a model declaring a blind-index key indexes under that key."""

        class DeclaredIndexUser(BaseModel, blind_index_key="model-level-index-key"):
            index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        assert DeclaredIndexUser.resolve_blind_index_key() == "model-level-index-key"

    def test_a_model_declaring_nothing_reads_the_environment(self):
        """Test that a model declaring no settings falls back to the configured ones."""

        class InheritedUser(BaseModel):
            secret: Annotated[str, Encrypted]

        assert InheritedUser.resolve_encryption_method() is EncryptionMethod.FERNET

    def test_a_model_with_no_encrypted_fields_decrypts_to_itself(self):
        """Test that decrypting a model carrying no encrypted field is a no-op returning self."""

        class PlainUser(BaseModel):
            name: str

        user = PlainUser(name="plain")

        assert user.decrypt_data() is user
        assert user.name == "plain"
