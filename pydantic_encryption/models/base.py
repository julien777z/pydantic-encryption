from typing import Annotated, Any, Optional, Union, get_args, get_origin, get_type_hints

from pydantic_super_model import SuperModel

from pydantic_encryption.adapters import encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.types import Decrypt, Encrypt, EncryptionMethod, Hash

__all__ = ["BaseModel", "SecureModel"]


class SecureModel:
    """Base class for encryptable and hashable models."""

    _disable: Optional[bool] = None

    def __init_subclass__(cls, *, disable: bool = False, **kwargs) -> None:
        cls._disable = disable
        super().__init_subclass__(**kwargs)

    def encrypt_data(self) -> None:
        """Encrypt data using the specified encryption method."""

        if self._disable:
            return

        if not self.pending_encryption_fields:
            return

        encrypted_data: dict[str, str] = {}

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.EVERVAULT:
                encrypted_data = encryption.evervault.EvervaultAdapter.encrypt(self.pending_encryption_fields)
            case EncryptionMethod.FERNET:
                encrypted_data = {
                    field_name: encryption.fernet.FernetAdapter.encrypt(value)
                    for field_name, value in self.pending_encryption_fields.items()
                }
            case EncryptionMethod.AWS:
                encrypted_data = {
                    field_name: encryption.aws.AWSAdapter.encrypt(value)
                    for field_name, value in self.pending_encryption_fields.items()
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

        match settings.ENCRYPTION_METHOD:
            case EncryptionMethod.EVERVAULT:
                decrypted_data = encryption.evervault.EvervaultAdapter.decrypt(self.pending_decryption_fields)
            case EncryptionMethod.FERNET:
                decrypted_data = {
                    field_name: encryption.fernet.FernetAdapter.decrypt(value)
                    for field_name, value in self.pending_decryption_fields.items()
                }
            case EncryptionMethod.AWS:
                decrypted_data = {
                    field_name: encryption.aws.AWSAdapter.decrypt(value)
                    for field_name, value in self.pending_decryption_fields.items()
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

        for field_name, value in self.pending_hash_fields.items():
            hashed = hashing.argon2.Argon2Adapter.hash(value)
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

    def get_annotated_fields(self, *annotations: type) -> dict[str, str]:
        """Get fields that have the specified annotations, handling union types."""

        def has_annotation(target_type, target_annotations):
            """Check if a type has any of the target annotations."""

            if any(target_type is ann or target_type == ann for ann in target_annotations):
                return True

            if get_origin(target_type) is Annotated:
                for arg in get_args(target_type)[1:]:
                    if any(arg is ann or arg == ann for ann in target_annotations):
                        return True

            return False

        type_hints = get_type_hints(type(self), include_extras=True)
        annotated_fields: dict[str, str] = {}

        for field_name, field_annotation in type_hints.items():
            found_annotation = False

            if has_annotation(field_annotation, annotations):
                found_annotation = True
            elif get_origin(field_annotation) is Union:
                for arg in get_args(field_annotation):
                    if has_annotation(arg, annotations):
                        found_annotation = True
                        break

            if found_annotation:
                field_value = getattr(self, field_name, None)
                if field_value is not None:
                    annotated_fields[field_name] = field_value

        return annotated_fields

    @classmethod
    def _get_class_parameter(cls, parameter_name: str) -> Any:
        """Get a class parameter from the class or its parent classes."""

        for base in cls.__mro__[1:]:
            if hasattr(base, parameter_name):
                return getattr(base, parameter_name)

        return None

    @property
    def pending_encryption_fields(self) -> dict[str, str]:
        """Get all encrypted fields from the model."""

        return self.get_annotated_fields(Encrypt)

    @property
    def pending_decryption_fields(self) -> dict[str, str]:
        """Get all decrypted fields from the model."""

        return self.get_annotated_fields(Decrypt)

    @property
    def pending_hash_fields(self) -> dict[str, str]:
        """Get all hashable fields from the model."""

        return self.get_annotated_fields(Hash)


class BaseModel(SuperModel, SecureModel):
    """Base model for encryptable models."""

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()

        super().model_post_init(context)
