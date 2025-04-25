from typing import Any, Annotated, get_type_hints, Union, get_args, get_origin, Optional
from enum import Enum
from cryptography.fernet import Fernet
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

if settings.ENCRYPTION_KEY:
    fernet = Fernet(settings.ENCRYPTION_KEY)
else:
    fernet = None


__all__ = [
    "Encrypt",
    "Decrypt",
    "Hash",
    "SecureModel",
    "EncryptionMethod",
]


class Encrypt:
    """Annotation to mark fields for encryption."""


class Decrypt:
    """Annotation to mark fields for decryption."""


class Hash:
    """Annotation to mark fields for hashing."""


class EncryptionMethod(Enum):
    """Enum for encryption methods."""

    FERNET = "fernet"
    EVERVAULT = "evervault"


class SecureModel:
    """Base class for encryptable and hashable models."""

    _disable: Optional[bool] = None
    _use_encryption_method: Optional[EncryptionMethod] = EncryptionMethod.FERNET

    def __init_subclass__(
        cls,
        disable: Optional[bool] = None,
        use_encryption_method: Optional[EncryptionMethod] = EncryptionMethod.FERNET,
        **kwargs,
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls._disable = disable
        cls._use_encryption_method = use_encryption_method

    def encrypt_data(self) -> None:
        """Encrypt data using the specified encryption method."""

        if self._disable:
            return

        if not self.pending_encryption_fields:
            return

        match self._use_encryption_method:
            case EncryptionMethod.EVERVAULT:
                if not evervault_client:
                    raise ValueError(
                        "Evervault is not available. Please install this package with the `evervault` extra."
                    )

                encrypted_data_dict = evervault_client.encrypt(
                    self.pending_encryption_fields,
                    role=settings.EVERVAULT_ENCRYPTION_ROLE,
                )

                for field_name, value in encrypted_data_dict.items():
                    setattr(self, field_name, value)

            case EncryptionMethod.FERNET:
                if not fernet:
                    raise ValueError(
                        "Fernet is not available. Please set the ENCRYPTION_KEY environment variable."
                    )

                encrypted_data_dict = {
                    field_name: fernet.encrypt(value.encode("utf-8")).decode("utf-8")
                    for field_name, value in self.pending_encryption_fields.items()
                }

                for field_name, value in encrypted_data_dict.items():
                    setattr(self, field_name, value)
            case _:
                raise ValueError(
                    f"Unknown encryption method: {self._use_encryption_method}"
                )

    def decrypt_data(self) -> None:
        """Decrypt data using the specified encryption method. After this call, all decrypted fields are type str."""

        if self._disable:
            return

        if not self.pending_decryption_fields:
            return

        match self._use_encryption_method:
            case EncryptionMethod.EVERVAULT:
                if not evervault_client:
                    raise ValueError(
                        "Evervault is not available. Please install this package with the `evervault` extra."
                    )

                decrypted_data: dict[str, str] = evervault_client.decrypt(
                    self.pending_decryption_fields,
                )

                for field_name, value in decrypted_data.items():
                    setattr(self, field_name, value)

            case EncryptionMethod.FERNET:
                if not fernet:
                    raise ValueError(
                        "Fernet is not available. Please set the ENCRYPTION_KEY environment variable."
                    )

                decrypted_data: dict[str, str] = {
                    field_name: fernet.decrypt(value.encode("utf-8")).decode("utf-8")
                    for field_name, value in self.pending_decryption_fields.items()
                }

                for field_name, value in decrypted_data.items():
                    setattr(self, field_name, value)

            case _:
                raise ValueError(
                    f"Unknown encryption method: {self._use_encryption_method}"
                )

    def hash_data(self) -> None:
        """Hash fields marked with `Hash` annotation."""

        if self._disable:
            return

        if not self.pending_hash_fields:
            return

        for field_name, value in self.pending_hash_fields.items():
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(value.encode("utf-8"), salt).decode("utf-8")

            setattr(self, field_name, hashed)

    @staticmethod
    def get_annotated_fields(
        instance: "BaseModel", obj: Optional[dict[str, Any]] = None, *annotations: type
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
