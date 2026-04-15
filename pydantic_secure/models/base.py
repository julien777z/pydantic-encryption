import asyncio
import contextvars
from typing import Any, Self

from pydantic_super_model import AnnotatedFieldInfo, SuperModelPydanticMixin

from pydantic_secure.adapters import hashing
from pydantic_secure.adapters.registry import get_blind_index_backend, get_encryption_backend
from pydantic_secure.config import settings
from pydantic_secure.normalization import normalize_value
from pydantic_secure.types import BlindIndex, BlindIndexValue, Encrypted, Hashed

__all__ = ["BaseModel", "SecureModel"]

_skip_sync_crypto: contextvars.ContextVar[bool] = contextvars.ContextVar("_skip_sync_crypto", default=False)


class SecureModel:
    """Base class for encryptable and hashable models."""

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

        if not self.pending_encryption_fields:
            return

        encryption_fields = self._get_field_values(self.pending_encryption_fields)

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)

        for field_name, value in encryption_fields.items():
            setattr(self, field_name, backend.encrypt(value))

    def hash_data(self) -> None:
        """Hash fields marked with `Hashed` annotation."""

        if not self.pending_hash_fields:
            return

        hash_fields = self._get_field_values(self.pending_hash_fields)

        for field_name, value in hash_fields.items():
            hashed = hashing.argon2.Argon2Adapter.hash(value)
            setattr(self, field_name, hashed)

    def blind_index_data(self) -> None:
        """Compute blind indexes for fields marked with `BlindIndex` annotation."""

        if not self.pending_blind_index_fields:
            return

        for field_name, annotated_field in self.pending_blind_index_fields.items():
            if annotated_field.value is None:
                continue

            annotation = annotated_field.matched_metadata[0]
            value = annotated_field.value

            if isinstance(value, BlindIndexValue):
                continue

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
                raise ValueError("BLIND_INDEX_SECRET_KEY must be set to use BlindIndex.")
            key_bytes = key.encode("utf-8")

            backend = get_blind_index_backend(annotation.method)
            setattr(self, field_name, backend.compute_blind_index(value, key_bytes))

    def decrypt_fields(self) -> Self:
        """Decrypt all Encrypted fields in-place. Returns self for chaining."""

        if not self.pending_encryption_fields:
            return self

        encryption_fields = self._get_field_values(self.pending_encryption_fields)

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)

        for field_name, value in encryption_fields.items():
            setattr(self, field_name, backend.decrypt(value))

        return self

    async def async_decrypt_fields(self) -> Self:
        """Asynchronously decrypt all Encrypted fields in-place. Returns self for chaining."""

        if not self.pending_encryption_fields:
            return self

        encryption_fields = self._get_field_values(self.pending_encryption_fields)

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
        tasks = {name: backend.async_decrypt(val) for name, val in encryption_fields.items()}

        results = await asyncio.gather(*tasks.values())
        for field_name, value in zip(tasks.keys(), results):
            setattr(self, field_name, value)

        return self

    def default_post_init(self) -> None:
        """Post initialization hook for encryption, hashing, and blind indexing."""

        if _skip_sync_crypto.get():
            return

        if self.pending_encryption_fields:
            self.encrypt_data()

        if self.pending_hash_fields:
            self.hash_data()

        if self.pending_blind_index_fields:
            self.blind_index_data()

    @property
    def pending_encryption_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get encrypted fields from the model."""

        return self.get_annotated_fields(Encrypted)

    @property
    def pending_hash_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get hashable fields from the model."""

        return self.get_annotated_fields(Hashed)

    @property
    def pending_blind_index_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Get blind index fields from the model."""

        return self.get_annotated_fields(BlindIndex)

    async def async_encrypt_data(self) -> None:
        """Asynchronously encrypt data using the specified encryption method."""

        if not self.pending_encryption_fields:
            return

        encryption_fields = self._get_field_values(self.pending_encryption_fields)

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")

        backend = get_encryption_backend(settings.ENCRYPTION_METHOD)
        tasks = {name: backend.async_encrypt(val) for name, val in encryption_fields.items()}

        results = await asyncio.gather(*tasks.values())
        for field_name, value in zip(tasks.keys(), results):
            setattr(self, field_name, value)

    async def async_hash_data(self) -> None:
        """Asynchronously hash fields marked with `Hashed` annotation."""

        if not self.pending_hash_fields:
            return

        hash_fields = self._get_field_values(self.pending_hash_fields)
        tasks = {
            name: hashing.argon2.Argon2Adapter.async_hash(val)
            for name, val in hash_fields.items()
        }
        results = await asyncio.gather(*tasks.values())

        for field_name, value in zip(tasks.keys(), results):
            setattr(self, field_name, value)

    async def async_blind_index_data(self) -> None:
        """Asynchronously compute blind indexes for fields marked with `BlindIndex` annotation."""

        if not self.pending_blind_index_fields:
            return

        tasks: dict[str, Any] = {}
        key_bytes: bytes | None = None

        for field_name, annotated_field in self.pending_blind_index_fields.items():
            if annotated_field.value is None:
                continue

            annotation = annotated_field.matched_metadata[0]
            value = annotated_field.value

            if isinstance(value, BlindIndexValue):
                continue

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

            if key_bytes is None:
                key = settings.BLIND_INDEX_SECRET_KEY
                if key is None:
                    raise ValueError("BLIND_INDEX_SECRET_KEY must be set to use BlindIndex.")
                key_bytes = key.encode("utf-8")

            backend = get_blind_index_backend(annotation.method)
            tasks[field_name] = backend.async_compute_blind_index(value, key_bytes)

        if tasks:
            results = await asyncio.gather(*tasks.values())
            for field_name, value in zip(tasks.keys(), results):
                setattr(self, field_name, value)

    async def async_post_init(self) -> None:
        """Asynchronously run all post-initialization operations."""

        # Recurse into nested SecureModel fields first (depth-first),
        # so nested models are fully processed before the parent.
        for field_name in getattr(type(self), "model_fields", {}):
            value = getattr(self, field_name, None)
            if isinstance(value, SecureModel):
                await value.async_post_init()
            elif isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    if isinstance(item, SecureModel):
                        await item.async_post_init()
            elif isinstance(value, dict):
                for item in value.values():
                    if isinstance(item, SecureModel):
                        await item.async_post_init()

        await self.async_encrypt_data()
        await self.async_hash_data()
        await self.async_blind_index_data()


class BaseModel(SuperModelPydanticMixin, SecureModel):
    """Base model for encryptable models."""

    def get_annotated_fields(self, *annotations: type) -> dict[str, AnnotatedFieldInfo]:
        """Return annotated field info objects keyed by field name."""

        return super().get_annotated_fields(*annotations)

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()

        super().model_post_init(context)

    @classmethod
    async def async_init(cls, /, **data: Any) -> Self:
        """Asynchronously construct a model with async encryption, hashing, and blind indexing."""

        token = _skip_sync_crypto.set(True)
        try:
            instance = cls(**data)
        finally:
            _skip_sync_crypto.reset(token)
        await instance.async_post_init()
        return instance
