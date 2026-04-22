import asyncio
from typing import Any, Awaitable, ClassVar, Self

from pydantic_super_model import AnnotatedFieldInfo, SuperModelPydanticMixin

from pydantic_encryption.adapters import hashing
from pydantic_encryption.adapters.base import BlindIndexAdapter, EncryptionAdapter
from pydantic_encryption.adapters.registry import get_blind_index_backend, get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.normalization import normalize_value
from pydantic_encryption.types import BlindIndex, BlindIndexValue, Encrypted, EncryptionMethod, Hashed

__all__ = ["BaseModel", "SecureModel"]


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
        """Return the encryption method for this class or raise if unset."""

        method = cls._encryption_method or settings.ENCRYPTION_METHOD
        if method is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")
        return method

    @classmethod
    def _resolve_encryption_key(cls) -> str | None:
        """Return the encryption key for this class, if any."""

        return cls._encryption_key or settings.ENCRYPTION_KEY

    @classmethod
    def _resolve_blind_index_key(cls) -> str:
        """Return the blind-index secret key for this class or raise if unset."""

        key = cls._blind_index_key or settings.BLIND_INDEX_SECRET_KEY
        if key is None:
            raise ValueError("BLIND_INDEX_SECRET_KEY must be set to use BlindIndex.")
        return key

    @property
    def pending_encryption_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Return fields annotated with ``Encrypted``."""

        return self.get_annotated_fields(Encrypted)

    @property
    def pending_hash_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Return fields annotated with ``Hashed``."""

        return self.get_annotated_fields(Hashed)

    @property
    def pending_blind_index_fields(self) -> dict[str, AnnotatedFieldInfo]:
        """Return fields annotated with ``BlindIndex``."""

        return self.get_annotated_fields(BlindIndex)

    @staticmethod
    def _nonempty_field_values(fields: dict[str, AnnotatedFieldInfo]) -> dict[str, Any]:
        """Extract raw values from annotated field info, dropping ``None`` entries."""

        return {
            field_name: annotated_field.value
            for field_name, annotated_field in fields.items()
            if annotated_field.value is not None
        }

    def _collect_encryption_fields(
        self,
    ) -> tuple[type[EncryptionAdapter], str | None, dict[str, Any]] | None:
        """Resolve encryption backend/key and collect field values."""

        if not self.pending_encryption_fields:
            return None

        fields = self._nonempty_field_values(self.pending_encryption_fields)
        if not fields:
            return None

        backend = get_encryption_backend(self._resolve_encryption_method())
        key = self._resolve_encryption_key()

        return backend, key, fields

    def _collect_hash_fields(self) -> dict[str, Any] | None:
        """Collect non-``None`` values for fields annotated with ``Hashed``."""

        if not self.pending_hash_fields:
            return None

        fields = self._nonempty_field_values(self.pending_hash_fields)
        return fields or None

    def _normalize_blind_index_value(self, annotation: BlindIndex, value: Any) -> str:
        """Decode bytes to str and apply the annotation's normalization flags."""

        if isinstance(value, bytes):
            value = value.decode("utf-8")

        return normalize_value(
            value,
            strip_whitespace=annotation.strip_whitespace,
            strip_non_characters=annotation.strip_non_characters,
            strip_non_digits=annotation.strip_non_digits,
            normalize_to_lowercase=annotation.normalize_to_lowercase,
            normalize_to_uppercase=annotation.normalize_to_uppercase,
        )

    def _collect_blind_index_tasks(
        self,
    ) -> list[tuple[str, type[BlindIndexAdapter], str, bytes]] | None:
        """Return ``(field_name, backend, normalized_value, key_bytes)`` tuples."""

        if not self.pending_blind_index_fields:
            return None

        tasks: list[tuple[str, type[BlindIndexAdapter], str, bytes]] = []
        key_bytes: bytes | None = None

        for field_name, annotated_field in self.pending_blind_index_fields.items():
            value = annotated_field.value
            if value is None or isinstance(value, BlindIndexValue):
                continue

            annotation: BlindIndex = annotated_field.matched_metadata[0]
            normalized = self._normalize_blind_index_value(annotation, value)

            if key_bytes is None:
                key_bytes = self._resolve_blind_index_key().encode("utf-8")

            backend = get_blind_index_backend(annotation.method)
            tasks.append((field_name, backend, normalized, key_bytes))

        return tasks or None

    async def _apply(self, items: list[tuple[str, Awaitable[Any]]]) -> None:
        """Await each coroutine concurrently and ``setattr`` its result onto ``self``."""

        if not items:
            return

        names = [name for name, _ in items]
        results = await asyncio.gather(*(coro for _, coro in items))
        for name, value in zip(names, results):
            setattr(self, name, value)

    async def encrypt_data(self) -> None:
        """Encrypt fields annotated with ``Encrypted`` in-place."""

        collected = self._collect_encryption_fields()
        if collected is None:
            return

        backend, key, fields = collected
        await self._apply(
            [(name, backend.encrypt(val, key=key)) for name, val in fields.items()]
        )

    async def hash_data(self) -> None:
        """Hash fields annotated with ``Hashed`` in-place."""

        fields = self._collect_hash_fields()
        if fields is None:
            return

        await self._apply(
            [(name, hashing.argon2.Argon2Adapter.hash(val)) for name, val in fields.items()]
        )

    async def blind_index_data(self) -> None:
        """Compute blind indexes for fields annotated with ``BlindIndex`` in-place."""

        tasks = self._collect_blind_index_tasks()
        if tasks is None:
            return

        await self._apply(
            [
                (name, backend.compute_blind_index(value, key_bytes))
                for name, backend, value, key_bytes in tasks
            ]
        )

    async def decrypt_data(self) -> Self:
        """Decrypt all ``Encrypted`` fields in-place and return ``self`` for chaining."""

        collected = self._collect_encryption_fields()
        if collected is None:
            return self

        backend, key, fields = collected
        await self._apply(
            [(name, backend.decrypt(val, key=key)) for name, val in fields.items()]
        )

        return self

    @staticmethod
    async def _post_init_nested(value: Any) -> None:
        """Recursively run ``post_init`` on nested ``SecureModel`` instances."""

        if isinstance(value, SecureModel):
            await value.post_init()
        elif isinstance(value, dict):
            await asyncio.gather(*(SecureModel._post_init_nested(v) for v in value.values()))
        elif isinstance(value, (list, tuple, set, frozenset)):
            await asyncio.gather(*(SecureModel._post_init_nested(v) for v in value))

    async def post_init(self) -> None:
        """Run encrypt + hash + blind-index concurrently, including on nested models."""

        children = [
            self._post_init_nested(value)
            for name in getattr(type(self), "model_fields", {})
            if (value := getattr(self, name, None)) is not None
        ]
        await asyncio.gather(
            *children,
            self.encrypt_data(),
            self.hash_data(),
            self.blind_index_data(),
        )


class BaseModel(SuperModelPydanticMixin, SecureModel):
    """Pydantic base model with async encryption, hashing, and blind indexing."""

    def get_annotated_fields(self, *annotations: type) -> dict[str, AnnotatedFieldInfo]:
        """Return annotated field info objects keyed by field name."""

        return super().get_annotated_fields(*annotations)

    @classmethod
    async def async_init(cls, /, **data: Any) -> Self:
        """Construct a model and run post_init to encrypt, hash, and blind-index annotated fields."""

        instance = cls(**data)
        await instance.post_init()
        return instance
