from typing import (
    Annotated,
    Optional,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    Any,
)

from pydantic_encryption.lib import argon2, fernet, evervault, aws
from pydantic_encryption.annotations import (
    Encrypt,
    Decrypt,
    Hash,
    EncryptionMethod,
    TableProvider,
)
from pydantic_encryption.models.adapters.sqlalchemy import (
    SQLAlchemyEncryptedString,
    SQLAlchemyHashedString,
)


__all__ = ["SecureModel"]


class SecureModel:
    """Base class for encryptable and hashable models."""

    _disable: Optional[bool] = None
    _use_encryption_method: Optional[EncryptionMethod] = None
    _use_table_provider: Optional[TableProvider] = None

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
            use_encryption_method = cls.get_class_parameter("_use_encryption_method")

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
                    field_name: fernet.fernet_encrypt(value)
                    for field_name, value in self.pending_encryption_fields.items()
                }
            case EncryptionMethod.AWS:
                encrypted_data = {
                    field_name: aws.aws_encrypt(value)
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
                    field_name: fernet.fernet_decrypt(value)
                    for field_name, value in self.pending_decryption_fields.items()
                }
            case EncryptionMethod.AWS:
                decrypted_data = {
                    field_name: aws.aws_decrypt(value)
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
            hashed = argon2.argon2_hash_data(value)

            setattr(self, field_name, hashed)

    def _handle_sqlalchemy(self) -> None:
        """Handle SQLAlchemy integration."""

        table = self.__class__.__table__  # pylint: disable=no-member

        def _override_type(column_name: str, new_type: type) -> None:
            if column_name in table.columns:
                table.columns[column_name].type = new_type

        for field_name in self.pending_encryption_fields:
            _override_type(
                field_name,
                SQLAlchemyEncryptedString(
                    encryption_method=self._use_encryption_method
                ),
            )

        for field_name in self.pending_hash_fields:
            _override_type(field_name, SQLAlchemyHashedString())

    def default_post_init(self) -> None:
        """Post initialization hook. If you make your own BaseModel, you must call this in model_post_init()."""

        if not self._disable:
            if (
                self._use_table_provider == TableProvider.SQLALCHEMY
                and not hasattr(self.__class__, "__table__")
            ) or (
                self._use_table_provider != TableProvider.SQLALCHEMY
                and hasattr(self.__class__, "__table__")
            ):
                raise ValueError(
                    "You must use the @sqlalchemy_table decorator on the SQLAlchemy table model."
                )

            if (
                hasattr(self.__class__, "__table__")
                and self._use_table_provider == TableProvider.SQLALCHEMY
            ):
                self._handle_sqlalchemy()
            else:
                # Regular models
                if self.pending_encryption_fields:
                    self.encrypt_data()

                if self.pending_hash_fields:
                    self.hash_data()

            if self.pending_decryption_fields:
                if self._use_table_provider == TableProvider.SQLALCHEMY:
                    raise ValueError(
                        "You must use Encrypt type for SQLAlchemy integration since it handles the encryption and decryption of the fields."
                    )

                self.decrypt_data()

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

            if found_annotation:
                field_value = getattr(self, field_name, None)

                if field_value is not None:
                    annotated_fields[field_name] = field_value

        return annotated_fields

    @classmethod
    def get_class_parameter(cls, parameter_name: str) -> Any:
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
