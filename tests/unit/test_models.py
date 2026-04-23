from typing import Annotated

from pydantic_super_model import AnnotatedFieldInfo

from pydantic_encryption import BaseModel, Encrypted, Hashed
from pydantic_encryption.types import EncryptedValue, HashedValue


class TestModelEncryption:
    """Test model encryption behavior."""

    def test_multiple_encrypted_fields(self):
        """Test model with multiple encrypted fields."""

        class _MultiEncrypt(BaseModel):
            field1: Annotated[bytes, Encrypted]
            field2: Annotated[bytes, Encrypted]
            field3: Annotated[bytes, Encrypted]

        model = _MultiEncrypt(field1="secret1", field2="secret2", field3="secret3")

        assert isinstance(model.field1, EncryptedValue)
        assert isinstance(model.field2, EncryptedValue)
        assert isinstance(model.field3, EncryptedValue)

    def test_optional_encrypted_field_with_value(self):
        """Test optional encrypted field with value."""

        class _OptionalEncrypt(BaseModel):
            secret: Annotated[bytes, Encrypted] | None = None

        model = _OptionalEncrypt(secret="my secret")

        assert isinstance(model.secret, EncryptedValue)

    def test_optional_encrypted_field_none(self):
        """Test optional encrypted field with None."""

        class _OptionalEncrypt(BaseModel):
            secret: Annotated[bytes, Encrypted] | None = None

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
            email: Annotated[bytes, Encrypted]
            password: Annotated[str, Hashed]

        model = _MixedModel(username="john", email="john@example.com", password="secret123")

        assert model.username == "john"
        assert isinstance(model.email, EncryptedValue)
        assert isinstance(model.password, HashedValue)

    def test_model_inheritance(self):
        """Test encryption works with model inheritance."""

        class _BaseUser(BaseModel):
            username: str

        class _SecureUser(_BaseUser):
            password: Annotated[str, Hashed]
            secret: Annotated[bytes, Encrypted]

        model = _SecureUser(username="john", password="pass123", secret="my secret")

        assert model.username == "john"
        assert isinstance(model.password, HashedValue)
        assert isinstance(model.secret, EncryptedValue)



class TestModelDecryption:
    """Test model decryption behavior using decrypt_data()."""

    def test_decrypt_data(self):
        """Test decrypting fields in-place."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        original = "secret data"
        model = _Model(data=original)

        assert isinstance(model.data, EncryptedValue)

        model.decrypt_data()

        assert model.data == original

    def test_decrypt_multiple_fields(self):
        """Test decrypting multiple fields."""

        class _Model(BaseModel):
            data1: Annotated[bytes, Encrypted]
            data2: Annotated[bytes, Encrypted]

        model = _Model(data1="secret1", data2="secret2")
        model.decrypt_data()

        assert model.data1 == "secret1"
        assert model.data2 == "secret2"

    def test_decrypt_data_returns_self(self):
        """Test decrypt_data returns self for chaining."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _Model(data="secret")
        result = model.decrypt_data()

        assert result is model


class TestModelSerialization:
    """Test model serialization with encryption."""

    def test_model_dump_contains_encrypted(self):
        """Test model_dump contains encrypted values."""

        class _EncryptModel(BaseModel):
            secret: Annotated[bytes, Encrypted]

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
            secret: Annotated[bytes, Encrypted]

        model = _EncryptModel(secret="plaintext")
        fields = model.get_annotated_fields(Encrypted)

        assert isinstance(fields["secret"], AnnotatedFieldInfo)
        assert fields["secret"].value == model.secret
        assert fields["secret"].matched_metadata == (Encrypted,)

    def test_includes_explicit_none_values_in_annotated_field_lookup(self):
        """Include explicit None values in annotated field info results."""

        class _EncryptModel(BaseModel):
            secret: Annotated[bytes, Encrypted] | None

        model = _EncryptModel(secret=None)

        fields = model.get_annotated_fields(Encrypted)

        assert isinstance(fields["secret"], AnnotatedFieldInfo)
        assert fields["secret"].value is None

    def test_omits_unset_default_none_values_from_annotated_field_lookup(self):
        """Omit unset default None values from annotated field info results."""

        class _EncryptModel(BaseModel):
            secret: Annotated[bytes, Encrypted] | None = None

        model = _EncryptModel()

        assert model.get_annotated_fields(Encrypted) == {}


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_empty_string_encryption(self):
        """Test encrypting empty string."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _Model(data="")

        assert isinstance(model.data, EncryptedValue)

    def test_whitespace_string_encryption(self):
        """Test encrypting whitespace string."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        model = _Model(data="   ")

        assert isinstance(model.data, EncryptedValue)

    def test_unicode_encryption(self):
        """Test encrypting unicode characters."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        original = "日本語 🔐 العربية"
        model = _Model(data=original)
        model.decrypt_data()

        assert model.data == original

    def test_long_string_encryption(self):
        """Test encrypting long string."""

        class _Model(BaseModel):
            data: Annotated[bytes, Encrypted]

        original = "x" * 10000
        model = _Model(data=original)
        model.decrypt_data()

        assert model.data == original
