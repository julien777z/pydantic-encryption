from typing import Annotated

from pydantic_super_model import AnnotatedFieldInfo

from pydantic_encryption import BaseModel, Encrypted


class TestAnnotatedFieldLookup:
    """Test annotated field lookup behavior."""

    def test_returns_encrypted_fields(self):
        """Test that the lookup returns annotated field info for encrypted fields."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted]

        model = _EncryptModel(secret="plaintext")
        fields = model.get_annotated_fields(Encrypted)

        assert isinstance(fields["secret"], AnnotatedFieldInfo)
        assert fields["secret"].value == model.secret
        assert fields["secret"].matched_metadata == (Encrypted,)

    def test_includes_explicit_none(self):
        """Test that a field explicitly set to None is included."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted] | None

        model = _EncryptModel(secret=None)

        fields = model.get_annotated_fields(Encrypted)

        assert isinstance(fields["secret"], AnnotatedFieldInfo)
        assert fields["secret"].value is None

    def test_omits_unset_default_none(self):
        """Test that a field left at its None default is omitted."""

        class _EncryptModel(BaseModel):
            secret: Annotated[str, Encrypted] | None = None

        model = _EncryptModel()

        assert model.get_annotated_fields(Encrypted) == {}
