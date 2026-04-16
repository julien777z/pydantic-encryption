import asyncio
import contextvars
from typing import Any, ClassVar, Self

from pydantic_super_model import AnnotatedFieldInfo, SuperModelPydanticMixin

from pydantic_secure.adapters import hashing
from pydantic_secure.adapters.registry import get_blind_index_backend, get_encryption_backend
from pydantic_secure.config import settings
from pydantic_secure.normalization import normalize_value
from pydantic_secure.types import BlindIndex, BlindIndexValue, Encrypted, EncryptionMethod, Hashed

__all__ = ["BaseModel", "SecureModel"]

_defer_crypto_to_async: contextvars.ContextVar[bool] = contextvars.ContextVar("_defer_crypto_to_async", default=False)


class SecureModel:
    """Base class for encryptable and hashable models."""

    _encryption_method: ClassVar[EncryptionMethod | None] = None
    _encryption_key: ClassVar[str | None] = None
    _blind_index_key: ClassVar[str | None] = None

    def __init_subclass__(
        cls,
        *,
        encryption_method: EncryptionMethod | str | None = None,
        encryption_key: str | None = None,
        blind_index_key: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)

        if encryption_method is not None:
            if isinstance(encryption_method, str):
                encryption_method = EncryptionMethod(encryption_method)
            cls._encryption_method = encryption_method

        if encryption_key is not None:
            cls._encryption_key = encryption_key

        if blind_index_key is not None:
            cls._blind_index_key = blind_index_key

    @classmethod
    def _resolve_encryption_method(cls) -> EncryptionMethod:
        method = cls._encryption_method or settings.ENCRYPTION_METHOD
        if method is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")
        return method

    @classmethod
    def _resolve_encryption_key(cls) -> str | None:
        return cls._encryption_key or settings.ENCRYPTION_KEY

    @classmethod
    def _resolve_blind_index_key(cls) -> str:
        key = cls._blind_index_key or settings.BLIND_INDEX_SECRET_KEY
        if key is None:
            raise ValueError("BLIND_INDEX_SECRET_KEY must be set to use BlindIndex.")
        return key

    @staticmethod
    def _get_field_values(fields: dict[str, AnnotatedFieldInfo]) -> dict[str, str]:
        """Extract raw values from annotated field info objects."""

        return {
            field_name: annotated_field.value
            for field_name, annotated_field in fields.items()
            if annotated_field.value is not None
        }

    # Collection helpers (shared by sync and async paths)

    def _collect_encryption_fields(self) -> tuple[type, str | None, dict[str, str]] | None:
        """Resolve encryption backend/key and collect field values. Returns None if nothing to do."""

        if not self.pending_encryption_fields:
            return None
        fields = self._get_field_values(self.pending_encryption_fields)
        if not fields:
            return None
        method = self._resolve_encryption_method()
        key = self._resolve_encryption_key()
        backend = get_encryption_backend(method)
        return backend, key, fields

    def _collect_hash_fields(self) -> dict[str, str] | None:
        """Collect hash field values. Returns None if nothing to do."""

        if not self.pending_hash_fields:
            return None
        fields = self._get_field_values(self.pending_hash_fields)
        return fields or None

    def _collect_blind_index_tasks(self) -> list[tuple[str, type, str, bytes]] | None:
        """Normalize values and resolve backends for blind index fields.

        Returns list of (field_name, backend, normalized_value, key_bytes) or None.
        """

        if not self.pending_blind_index_fields:
            return None

        result = []
        key_bytes: bytes | None = None

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

            if key_bytes is None:
                key_bytes = self._resolve_blind_index_key().encode("utf-8")

            backend = get_blind_index_backend(annotation.method)
            result.append((field_name, backend, value, key_bytes))

        return result or None

    # Sync methods

    def encrypt_data(self) -> None:
        """Encrypt data using the specified encryption method."""

        collected = self._collect_encryption_fields()
        if collected is None:
            return
        backend, key, fields = collected

        for field_name, value in fields.items():
            setattr(self, field_name, backend.encrypt(value, key=key))

    def hash_data(self) -> None:
        """Hash fields marked with `Hashed` annotation."""

        fields = self._collect_hash_fields()
        if fields is None:
            return

        for field_name, value in fields.items():
            setattr(self, field_name, hashing.argon2.Argon2Adapter.hash(value))

    def blind_index_data(self) -> None:
        """Compute blind indexes for fields marked with `BlindIndex` annotation."""

        tasks = self._collect_blind_index_tasks()
        if tasks is None:
            return

        for field_name, backend, value, key_bytes in tasks:
            setattr(self, field_name, backend.compute_blind_index(value, key_bytes))

    def decrypt_fields(self) -> Self:
        """Decrypt all Encrypted fields in-place. Returns self for chaining."""

        collected = self._collect_encryption_fields()
        if collected is None:
            return self
        backend, key, fields = collected

        for field_name, value in fields.items():
            setattr(self, field_name, backend.decrypt(value, key=key))

        return self

    # Async methods

    async def async_encrypt_data(self) -> None:
        """Asynchronously encrypt data using the specified encryption method."""

        collected = self._collect_encryption_fields()
        if collected is None:
            return
        backend, key, fields = collected
        coros = {name: backend.async_encrypt(val, key=key) for name, val in fields.items()}

        results = await asyncio.gather(*coros.values())
        for field_name, value in zip(coros.keys(), results):
            setattr(self, field_name, value)

    async def async_hash_data(self) -> None:
        """Asynchronously hash fields marked with `Hashed` annotation."""

        fields = self._collect_hash_fields()
        if fields is None:
            return

        coros = {name: hashing.argon2.Argon2Adapter.async_hash(val) for name, val in fields.items()}
        results = await asyncio.gather(*coros.values())

        for field_name, value in zip(coros.keys(), results):
            setattr(self, field_name, value)

    async def async_blind_index_data(self) -> None:
        """Asynchronously compute blind indexes for fields marked with `BlindIndex` annotation."""

        tasks = self._collect_blind_index_tasks()
        if tasks is None:
            return

        coros = {
            field_name: backend.async_compute_blind_index(value, key_bytes)
            for field_name, backend, value, key_bytes in tasks
        }
        results = await asyncio.gather(*coros.values())
        for field_name, value in zip(coros.keys(), results):
            setattr(self, field_name, value)

    async def async_decrypt_fields(self) -> Self:
        """Asynchronously decrypt all Encrypted fields in-place. Returns self for chaining."""

        collected = self._collect_encryption_fields()
        if collected is None:
            return self
        backend, key, fields = collected
        coros = {name: backend.async_decrypt(val, key=key) for name, val in fields.items()}

        results = await asyncio.gather(*coros.values())
        for field_name, value in zip(coros.keys(), results):
            setattr(self, field_name, value)

        return self

    # Post-init hooks

    def default_post_init(self) -> None:
        """Post initialization hook for encryption, hashing, and blind indexing."""

        if _defer_crypto_to_async.get():
            return

        self.encrypt_data()
        self.hash_data()
        self.blind_index_data()

    @staticmethod
    async def _async_post_init_nested(value: Any) -> None:
        """Recursively walk containers to find and process nested SecureModel instances."""

        if isinstance(value, SecureModel):
            await value.async_post_init()
        elif isinstance(value, dict):
            for item in value.values():
                await SecureModel._async_post_init_nested(item)
        elif isinstance(value, (list, tuple, set, frozenset)):
            for item in value:
                await SecureModel._async_post_init_nested(item)

    async def async_post_init(self) -> None:
        """Asynchronously run all post-initialization operations."""

        # Recurse into nested SecureModel fields first (depth-first),
        # so nested models are fully processed before the parent.
        for field_name in getattr(type(self), "model_fields", {}):
            value = getattr(self, field_name, None)
            if value is not None:
                await self._async_post_init_nested(value)

        await self.async_encrypt_data()
        await self.async_hash_data()
        await self.async_blind_index_data()

    # Field introspection

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

        token = _defer_crypto_to_async.set(True)
        try:
            instance = cls(**data)
        finally:
            _defer_crypto_to_async.reset(token)
        await instance.async_post_init()
        return instance
