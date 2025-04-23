from enum import Enum, auto
from typing import (
    Any,
    Annotated,
    get_type_hints,
    Union,
    get_args,
    get_origin,
)
from pydantic_encryption.config import settings

try:
    import evervault
except ImportError:
    evervault_client = None
else:
    evervault_client = evervault.Client(app_uuid=settings.EVERVAULT_APP_ID, api_key=settings.EVERVAULT_API_KEY)

__all__ = ["EncryptionMode", "EncryptedField", "EncryptedModel", "DecryptedModel", "EncryptableObject"]

class EncryptionMode(Enum):
    """Controls whether to encrypt or decrypt the fields."""

    ENCRYPT = auto()
    DECRYPT = auto()

class _EncryptedFieldValue:
    pass


EncryptedField = Annotated[str, _EncryptedFieldValue]


class EncryptableObject:
    """Base class for encryptable models."""

    _encryption: EncryptionMode | None = None

    def __init_subclass__(cls, encryption: EncryptionMode | None = None, **kwargs):
        super().__init_subclass__(**kwargs)

        parent_encryption = getattr(cls.__mro__[1], "_encryption", None)

        cls._encryption = encryption or parent_encryption

    def encrypt_data(self) -> None:
        """Encrypt data using Evervault."""

        if self._encryption != EncryptionMode.ENCRYPT:
            raise ValueError("Encryption is not enabled for this model.")

        if not evervault_client:
            raise ValueError("Evervault is not available. Please install this package with the `evervault` extra.")

        encrypted_fields = self.get_encrypted_fields()
        encrypted_data_dict = evervault_client.encrypt(encrypted_fields, role=settings.EVERVAULT_ENCRYPTION_ROLE)

        for field_name, value in encrypted_data_dict.items():
            setattr(self, field_name, value)

    def decrypt_data(self) -> None:
        """Decrypt data using Evervault. After this call, all decrypted fields are type str."""

        if self._encryption != EncryptionMode.DECRYPT:
            raise ValueError("Decryption is not enabled for this model.")

        if not evervault_client:
            raise ValueError("Evervault is not available. Please install this package with the `evervault` extra.")

        encrypted_fields = self.get_encrypted_fields()
        decrypted_data: dict[str, str] = evervault_client.decrypt(encrypted_fields)

        for field_name, value in decrypted_data.items():
            setattr(self, field_name, value)

    @staticmethod
    def get_annotated_fields(
        instance: "BaseModel", obj: dict[str, Any] | None = None, *annotations: type
    ) -> dict[str, str]:
        """Get fields that have the specified annotations, handling union types.

        Args:
            instance: The instance to get annotated fields from
            obj: The object to get annotated fields from
            annotations: The annotations to look for

        Returns:
            A dictionary of field names to field values
        """

        def has_annotation(target_type, target_annotations):
            """Check if a type has any of the target annotations."""

            # Direct match
            if any(target_type is ann or target_type == ann for ann in target_annotations):
                return True

            # Annotated type
            if get_origin(target_type) is Annotated:
                for arg in get_args(target_type)[1:]:  # Skip first arg (the type)
                    if any(arg is ann or arg == ann for ann in target_annotations):
                        return True

            return False

        obj = obj or {}
        type_hints = get_type_hints(instance, include_extras=True)
        annotated_fields: dict[str, str] = {}

        for field_name, field_annotation in type_hints.items():
            found_annotation = False

            # Direct check
            if has_annotation(field_annotation, annotations):
                found_annotation = True

            # Check union types
            elif get_origin(field_annotation) is Union:
                for arg in get_args(field_annotation):

                    if has_annotation(arg, annotations):
                        found_annotation = True

                        break

            # If annotation found, add field value to result
            if found_annotation:
                field_value = None

                if field_name in obj:
                    field_value = obj[field_name]

                elif hasattr(instance, field_name):
                    field_value = getattr(instance, field_name)

                if field_value is not None:
                    annotated_fields[field_name] = field_value

        return annotated_fields

    def get_encrypted_fields(self) -> dict[str, str]:
        """Get all encrypted fields from the model."""

        return self.get_annotated_fields(self, None, _EncryptedFieldValue)


class EncryptedModel(EncryptableObject, encryption=EncryptionMode.ENCRYPT):
    """Base model for encrypted models."""


class DecryptedModel(EncryptableObject, encryption=EncryptionMode.DECRYPT):
    """Base model for decrypted models."""
