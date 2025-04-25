from typing import (
    Any,
    Annotated,
    get_type_hints,
    Union,
    get_args,
    get_origin,
)
import bcrypt
from pydantic_encryption.config import settings
from pydantic import BaseModel

try:
    import evervault
except ImportError:
    evervault_client = None
else:
    evervault_client = evervault.Client(
        app_uuid=settings.EVERVAULT_APP_ID, api_key=settings.EVERVAULT_API_KEY
    )

__all__ = [
    "Encrypt",
    "Decrypt",
    "Hash",
    "SecureModel",
]


class Encrypt:
    """Annotation to mark fields for encryption."""


class Decrypt:
    """Annotation to mark fields for decryption."""


class Hash:
    """Annotation to mark fields for hashing."""


class SecureModel:
    """Base class for encryptable and hashable models."""

    _disable: bool | None = None

    def __init_subclass__(cls, disable: bool | None = None, **kwargs):
        super().__init_subclass__(**kwargs)

        cls._disable = disable

    def encrypt_data(self) -> None:
        """Encrypt data using Evervault."""

        if self._disable:
            return

        if not evervault_client:
            raise ValueError(
                "Evervault is not available. Please install this package with the `evervault` extra."
            )

        if not self.pending_encryption_fields:
            return

        encrypted_data_dict = evervault_client.encrypt(
            self.pending_encryption_fields, role=settings.EVERVAULT_ENCRYPTION_ROLE
        )

        for field_name, value in encrypted_data_dict.items():
            setattr(self, field_name, value)

    def decrypt_data(self) -> None:
        """Decrypt data using Evervault. After this call, all decrypted fields are type str."""

        if self._disable:
            return

        if not evervault_client:
            raise ValueError(
                "Evervault is not available. Please install this package with the `evervault` extra."
            )

        if not self.pending_decryption_fields:
            return

        decrypted_data: dict[str, str] = evervault_client.decrypt(
            self.pending_decryption_fields
        )

        for field_name, value in decrypted_data.items():
            setattr(self, field_name, value)

    def hash_data(self) -> None:
        """Hash fields marked with `Hash` annotation."""

        if self._disable:
            return

        if not self.pending_hash_fields:
            return

        for field_name, value in self.pending_hash_fields.items():
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(value.encode("utf-8"), salt)

            setattr(self, field_name, hashed)

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
            if any(
                target_type is ann or target_type == ann for ann in target_annotations
            ):
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

    @property
    def pending_encryption_fields(self) -> dict[str, str]:
        """Get all encrypted fields from the model."""

        return self.get_annotated_fields(self, None, Encrypt)

    @property
    def pending_decryption_fields(self) -> dict[str, str]:
        """Get all decrypted fields from the model."""

        return self.get_annotated_fields(self, None, Decrypt)

    @property
    def pending_hash_fields(self) -> dict[str, str]:
        """Get all hashable fields from the model."""

        return self.get_annotated_fields(self, None, Hash)
