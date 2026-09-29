from typing import Annotated

from pydantic_encryption import BaseModel, BlindIndex, BlindIndexMethod, Encrypted
from pydantic_encryption.config import settings
from pydantic_encryption.types import EncryptionMethod


class TestModelLevelConfig:
    """Test the encryption settings a model declares for itself."""

    def test_string_method_resolves_to_enum(self, fernet_key: str):
        """Test that a model naming its method as a string resolves it to the enum."""

        class StringMethodUser(BaseModel, encryption_method="fernet", encryption_key=fernet_key):
            secret: Annotated[str, Encrypted]

        assert StringMethodUser.resolve_encryption_method() is EncryptionMethod.FERNET

    def test_declared_key_overrides_environment(self, fernet_key: str):
        """Test that a model declaring its own key seals under that key rather than the configured one."""

        class DeclaredKeyUser(
            BaseModel, encryption_method=EncryptionMethod.FERNET, encryption_key=fernet_key
        ):
            secret: Annotated[str, Encrypted]

        user = DeclaredKeyUser(secret="secret data")

        assert DeclaredKeyUser.resolve_encryption_key() == fernet_key
        assert user.decrypt_data().secret == "secret data"

    def test_declared_blind_index_key_overrides_environment(self):
        """Test that a model declaring a blind-index key indexes under that key."""

        class DeclaredIndexUser(BaseModel, blind_index_key="model-level-index-key"):
            index: Annotated[bytes, BlindIndex(BlindIndexMethod.HMAC_SHA256)]

        assert DeclaredIndexUser.resolve_blind_index_key() == "model-level-index-key"

    def test_undeclared_model_reads_environment(self):
        """Test that a model declaring no settings falls back to the configured ones."""

        class InheritedUser(BaseModel):
            secret: Annotated[str, Encrypted]

        assert InheritedUser.resolve_encryption_method() is EncryptionMethod.FERNET

    def test_no_encrypted_fields_decrypts_to_self(self):
        """Test that decrypting a model carrying no encrypted field is a no-op returning self."""

        class PlainUser(BaseModel):
            name: str

        user = PlainUser(name="plain")

        assert user.decrypt_data() is user
        assert user.name == "plain"
