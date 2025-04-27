from typing import (
    Annotated,
    Optional,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

from pydantic_encryption.lib import bcrypt, fernet, evervault
from pydantic_encryption.annotations import (
    Encrypt,
    Decrypt,
    Hash,
    EncryptionMethod,
)


__all__ = ["SecureModel"]


class SecureModel:
    """Base class for encryptable and hashable models."""

    _disable: Optional[bool] = None
    _use_encryption_method: Optional[EncryptionMethod] = None

    def __init_subclass__(
        cls,
        *,
        disable: bool = False,
        use_encryption_method: Optional[EncryptionMethod] = None,
        **kwargs,
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls._disable = disable

        if use_encryption_method is None:
            for base in cls.__mro__[1:]:
                ue = getattr(base, "_use_encryption_method", None)
                if ue is not None:
                    use_encryption_method = ue
                    break

        cls._use_encryption_method = use_encryption_method or EncryptionMethod.FERNET

    def encrypt_data(self) -> None:
        """Encrypt data using the specified encryption method."""

        if self._disable:
            return

        if not self.pending_encryption_fields:
            return

        encrypted_data: dict[str, str] = {}

        match self._use_encryption_method:
            case EncryptionMethod.EVERVAULT:
                encrypted_data = evervault.evervault_encrypt(
                    self.pending_encryption_fields
                )

            case EncryptionMethod.FERNET:
                encrypted_data = {
                    field_name: fernet.fernet_encrypt(value.encode("utf-8")).decode(
                        "utf-8"
                    )
                    for field_name, value in self.pending_encryption_fields.items()
                }
            case _:
                raise ValueError(
                    f"Unknown encryption method: {self._use_encryption_method}"
                )

        for field_name, value in encrypted_data.items():
            setattr(self, field_name, value)

    def decrypt_data(self) -> None:
        """Decrypt data using the specified encryption method. After this call, all decrypted fields are type str."""

        if self._disable:
            return

        if not self.pending_decryption_fields:
            return

        decrypted_data: dict[str, str] = {}

        match self._use_encryption_method:
            case EncryptionMethod.EVERVAULT:
                decrypted_data = evervault.evervault_decrypt(
                    self.pending_decryption_fields
                )

            case EncryptionMethod.FERNET:
                decrypted_data = {
                    field_name: fernet.fernet_decrypt(value.encode("utf-8")).decode(
                        "utf-8"
                    )
                    for field_name, value in self.pending_decryption_fields.items()
                }

            case _:
                raise ValueError(
                    f"Unknown encryption method: {self._use_encryption_method}"
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
            hashed = bcrypt.bcrypt_hash_data(value)

            setattr(self, field_name, hashed)

    def default_post_init(self) -> None:
        """Post initialization hook. If you make your own BaseModel, you must call this in model_post_init()."""

        if not self._disable:
            if self.pending_decryption_fields:
                self.decrypt_data()

            if self.pending_encryption_fields:
                self.encrypt_data()

            if self.pending_hash_fields:
                self.hash_data()

    def get_annotated_fields(self, *annotations: type) -> dict[str, str]:
        """Get fields that have the specified annotations, handling union types.

        Args:
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

        type_hints = get_type_hints(type(self), include_extras=True)
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
                annotated_fields[field_name] = getattr(self, field_name)

        return annotated_fields

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
