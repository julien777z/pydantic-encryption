from typing import Any

from pydantic_super_model import AnnotatedFieldInfo, SuperModel

from pydantic_encryption.adapters import encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.types import Decrypt, Encrypt, EncryptionMethod, Hash

__all__ = ["BaseModel", "SecureModel"]


class SecureModel:
    """Base class for encryptable and hashable models."""

    _disable: bool | None = None

    def __init_subclass__(cls, *, disable: bool = False, **kwargs) -> None:
        cls._disable = disable
        super().__init_subclass__(**kwargs)

    @staticmethod
    def _get_field_values(fields: dict[str, AnnotatedFieldInfo]) -> dict[str, str]:
        """Extract raw values from annotated field info objects."""

        return {
            field_name: annotated_field.value
            for field_name, annotated_field in fields.items()
            if annotated_field.value is not None
        }

    def encrypt_data(self) -> None:
        """Encrypt data using the specified encryption method."""

        if self._disable:
            return

        if not self.pending_encryption_fields:
            return

        encrypted_data: dict[str, str] = {}
        encryption_fields = self._get_field_values(self.pending_encryption_fields)

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.EVERVAULT:
                encrypted_data = encryption.evervault.EvervaultAdapter.encrypt(encryption_fields)
            case EncryptionMethod.FERNET:
                encrypted_data = {
                    field_name: encryption.fernet.FernetAdapter.encrypt(value)
                    for field_name, value in encryption_fields.items()
                }
            case EncryptionMethod.AWS:
                encrypted_data = {
                    field_name: encryption.aws.AWSAdapter.encrypt(value)
                    for field_name, value in encryption_fields.items()
                }
            case _:
                raise ValueError(f"Unknown encryption method: {settings.ENCRYPTION_METHOD}")

        for field_name, value in encrypted_data.items():
            setattr(self, field_name, value)

    def decrypt_data(self) -> None:
        """Decrypt data using the specified encryption method."""

        if self._disable:
            return

        if not self.pending_decryption_fields:
            return

        decrypted_data: dict[str, str] = {}
        decryption_fields = self._get_field_values(self.pending_decryption_fields)

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.EVERVAULT:
                decrypted_data = encryption.evervault.EvervaultAdapter.decrypt(decryption_fields)
            case EncryptionMethod.FERNET:
                decrypted_data = {
                    field_name: encryption.fernet.FernetAdapter.decrypt(value)
                    for field_name, value in decryption_fields.items()
                }
            case EncryptionMethod.AWS:
                decrypted_data = {
                    field_name: encryption.aws.AWSAdapter.decrypt(value)
                    for field_name, value in decryption_fields.items()
                }
            case _:
                raise ValueError(f"Unknown encryption method: {settings.ENCRYPTION_METHOD}")

        for field_name, value in decrypted_data.items():
            setattr(self, field_name, value)

    def hash_data(self) -> None:
        """Hash fields marked with `Hash` annotation."""

        if self._disable:
            return

        if not self.pending_hash_fields:
            return

        for field_name, annotated_field in self.pending_hash_fields.items():
            hashed = hashing.argon2.Argon2Adapter.hash(annotated_field.value)
            setattr(self, field_name, hashed)

    def default_post_init(self) -> None:
        """Post initialization hook. If you make your own BaseModel, you must call this in model_post_init()."""

        if not self._disable:
            if self.pending_encryption_fields:
                self.encrypt_data()

            if self.pending_hash_fields:
                self.hash_data()

            if self.pending_decryption_fields:
                self.decrypt_data()

    @classmethod
    def _get_class_parameter(cls, parameter_name: str) -> Any:
        """Get a class parameter from the class or its parent classes."""

        for base in cls.__mro__[1:]:
            if hasattr(base, parameter_name):
                return getattr(base, parameter_name)

        return None

    @property
    def pending_encryption_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get encrypted fields from the model."""

        return self.get_annotated_fields(Encrypt)

    @property
    def pending_decryption_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get decrypted fields from the model."""

        return self.get_annotated_fields(Decrypt)

    @property
    def pending_hash_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get hashable fields from the model."""

        return self.get_annotated_fields(Hash)


class BaseModel(SuperModel, SecureModel):
    """Base model for encryptable models."""

    def get_annotated_fields(self, *annotations: type) -> dict[str, AnnotatedFieldInfo]:
        """Return annotated field info objects keyed by field name."""

        return super().get_annotated_fields(*annotations)

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()

        super().model_post_init(context)
