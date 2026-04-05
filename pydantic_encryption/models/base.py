from typing import Any

from pydantic_super_model import AnnotatedFieldInfo, SuperModel

from pydantic_encryption.adapters import blind_index, encryption, hashing
from pydantic_encryption.config import settings
from pydantic_encryption.normalization import normalize_value
from pydantic_encryption.types import BlindIndex, BlindIndexMethod, Decrypt, Encrypt, EncryptionMethod, Hash

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

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypt fields.")

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

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Decrypt fields.")

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

        hash_fields = self._get_field_values(self.pending_hash_fields)

        for field_name, value in hash_fields.items():
            hashed = hashing.argon2.Argon2Adapter.hash(value)
            setattr(self, field_name, hashed)

    def blind_index_data(self) -> None:
        """Compute blind indexes for fields marked with `BlindIndex` annotation."""

        if self._disable:
            return

        if not self.pending_blind_index_fields:
            return

        for field_name, annotated_field in self.pending_blind_index_fields.items():
            if annotated_field.value is None:
                continue

            annotation = annotated_field.matched_metadata[0]
            value = annotated_field.value

            # Pydantic may convert str to bytes for bytes-typed fields,
            # so decode back to str for normalization
            if isinstance(value, bytes):
                value = value.decode("utf-8")

            value = normalize_value(
                value,
                strip_whitespace=annotation.strip_whitespace,
                strip_non_characters=annotation.strip_non_characters,
                strip_non_digits=annotation.strip_non_digits,
                normalize_to_lowercase=annotation.normalize_to_lowercase,
                normalize_to_uppercase=annotation.normalize_to_uppercase,
            )

            key = settings.BLIND_INDEX_SECRET_KEY
            if key is None:
                raise ValueError(
                    "BLIND_INDEX_SECRET_KEY must be set to use BlindIndex. "
                    "Set it via environment variable or .env file."
                )
            key_bytes = key.encode("utf-8")

            match annotation.method:
                case BlindIndexMethod.HMAC_SHA256:
                    result = blind_index.hmac_sha256.HMACSHA256Adapter.compute_blind_index(value, key_bytes)
                case BlindIndexMethod.ARGON2:
                    from pydantic_encryption.adapters.blind_index.argon2 import Argon2BlindIndexAdapter

                    result = Argon2BlindIndexAdapter.compute_blind_index(value, key_bytes)
                case _:
                    raise ValueError(f"Unknown blind index method: {annotation.method}")

            setattr(self, field_name, result)

    def default_post_init(self) -> None:
        """Post initialization hook for encryption, hashing, and blind indexing."""

        if not self._disable:
            if self.pending_encryption_fields:
                self.encrypt_data()

            if self.pending_hash_fields:
                self.hash_data()

            if self.pending_blind_index_fields:
                self.blind_index_data()

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

    @property
    def pending_blind_index_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get blind index fields from the model."""

        return self.get_annotated_fields(BlindIndex)


class BaseModel(SuperModel, SecureModel):
    """Base model for encryptable models."""

    def get_annotated_fields(self, *annotations: type) -> dict[str, AnnotatedFieldInfo]:
        """Return annotated field info objects keyed by field name."""

        return super().get_annotated_fields(*annotations)

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()

        super().model_post_init(context)
