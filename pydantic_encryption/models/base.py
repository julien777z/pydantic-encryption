import asyncio
import contextvars
from collections.abc import Awaitable
from typing import Any, ClassVar, Self

from pydantic_super_model import AnnotatedFieldInfo, SuperModelPydanticMixin

from pydantic_encryption.adapters.base import BlindIndexAdapter, EncryptionAdapter
from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.adapters.registry import get_blind_index_backend, get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.normalization import normalize_value
from pydantic_encryption.types import BlindIndex, BlindIndexValue, Encrypted, EncryptionMethod, Hashed

__all__ = ["BaseModel", "SecureModel"]

defer_crypto_to_async: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "defer_crypto_to_async", default=False
)


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
    def resolve_encryption_method(cls) -> EncryptionMethod:
        """Return the per-class override or the ENCRYPTION_METHOD env value."""

        method = cls._encryption_method or settings.ENCRYPTION_METHOD
        if method is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use Encrypted fields.")

        return method

    @classmethod
    def resolve_encryption_key(cls) -> str | None:
        """Return the per-class override or the ENCRYPTION_KEY env value."""

        return cls._encryption_key or settings.ENCRYPTION_KEY

    @classmethod
    def resolve_blind_index_key(cls) -> str:
        """Return the per-class override or the BLIND_INDEX_SECRET_KEY env value."""

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
    def nonempty_field_values(fields: dict[str, AnnotatedFieldInfo]) -> dict[str, Any]:
        """Extract raw values from annotated field info, dropping ``None`` entries."""

        return {
            field_name: annotated_field.value
            for field_name, annotated_field in fields.items()
            if annotated_field.value is not None
        }

    def collect_encryption_fields(
        self,
    ) -> tuple[type[EncryptionAdapter], str | None, dict[str, Any]] | None:
        """Resolve encryption backend/key and collect field values."""

        if not self.pending_encryption_fields:
            return None

        fields = self.nonempty_field_values(self.pending_encryption_fields)
        if not fields:
            return None

        backend = get_encryption_backend(self.resolve_encryption_method())
        key = self.resolve_encryption_key()

        return backend, key, fields

    def collect_hash_fields(self) -> dict[str, Any] | None:
        """Collect non-``None`` values for fields annotated with ``Hashed``."""

        if not self.pending_hash_fields:
            return None

        fields = self.nonempty_field_values(self.pending_hash_fields)
        return fields or None

    def normalize_blind_index_value(self, annotation: BlindIndex, value: Any) -> str:
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

    def collect_blind_index_tasks(
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
            normalized = self.normalize_blind_index_value(annotation, value)

            if key_bytes is None:
                key_bytes = self.resolve_blind_index_key().encode("utf-8")

            backend = get_blind_index_backend(annotation.method)
            tasks.append((field_name, backend, normalized, key_bytes))

        return tasks or None

    async def async_apply(self, items: list[tuple[str, Awaitable[Any]]]) -> None:
        """Await each coroutine under a TaskGroup and ``setattr`` its result onto ``self``."""

        if not items:
            return

        async with asyncio.TaskGroup() as tg:
            tasks = [(name, tg.create_task(coro)) for name, coro in items]

        for name, task in tasks:
            setattr(self, name, task.result())

    def encrypt_data(self) -> None:
        """Encrypt fields annotated with ``Encrypted`` in-place."""

        collected = self.collect_encryption_fields()
        if collected is None:
            return

        backend, key, fields = collected
        for field_name, value in fields.items():
            setattr(self, field_name, backend.encrypt(value, key=key))

    def hash_data(self) -> None:
        """Hash fields annotated with ``Hashed`` in-place."""

        fields = self.collect_hash_fields()
        if fields is None:
            return

        for field_name, value in fields.items():
            setattr(self, field_name, Argon2Adapter.hash(value))

    def blind_index_data(self) -> None:
        """Compute blind indexes for fields annotated with ``BlindIndex`` in-place."""

        tasks = self.collect_blind_index_tasks()
        if tasks is None:
            return

        for field_name, backend, value, key_bytes in tasks:
            setattr(self, field_name, backend.compute_blind_index(value, key_bytes))

    def decrypt_data(self) -> Self:
        """Decrypt all ``Encrypted`` fields in-place and return ``self`` for chaining."""

        collected = self.collect_encryption_fields()
        if collected is None:
            return self

        backend, key, fields = collected
        for field_name, value in fields.items():
            setattr(self, field_name, backend.decrypt(value, key=key))

        return self

    async def async_encrypt_data(self) -> None:
        """Asynchronously encrypt fields annotated with ``Encrypted``."""

        collected = self.collect_encryption_fields()
        if collected is None:
            return

        backend, key, fields = collected
        await self.async_apply(
            [(name, backend.async_encrypt(val, key=key)) for name, val in fields.items()]
        )

    async def async_hash_data(self) -> None:
        """Asynchronously hash fields annotated with ``Hashed``."""

        fields = self.collect_hash_fields()
        if fields is None:
            return

        await self.async_apply(
            [(name, Argon2Adapter.async_hash(val)) for name, val in fields.items()]
        )

    async def async_blind_index_data(self) -> None:
        """Asynchronously compute blind indexes for fields annotated with ``BlindIndex``."""

        tasks = self.collect_blind_index_tasks()
        if tasks is None:
            return

        await self.async_apply(
            [
                (name, backend.async_compute_blind_index(value, key_bytes))
                for name, backend, value, key_bytes in tasks
            ]
        )

    async def async_decrypt_data(self) -> Self:
        """Asynchronously decrypt all ``Encrypted`` fields and return ``self`` for chaining."""

        collected = self.collect_encryption_fields()
        if collected is None:
            return self

        backend, key, fields = collected
        await self.async_apply(
            [(name, backend.async_decrypt(val, key=key)) for name, val in fields.items()]
        )

        return self

    def default_post_init(self) -> None:
        """Post-initialization hook that runs sync encrypt + hash + blind-index."""

        if defer_crypto_to_async.get():
            return

        self.encrypt_data()
        self.hash_data()
        self.blind_index_data()

    @staticmethod
    async def async_post_init_nested(value: Any) -> None:
        """Recursively run ``async_post_init`` on nested ``SecureModel`` instances."""

        if isinstance(value, SecureModel):
            await value.async_post_init()
            return

        if isinstance(value, dict):
            children: Any = value.values()
        elif isinstance(value, (list, tuple, set, frozenset)):
            children = value
        else:
            return

        async with asyncio.TaskGroup() as tg:
            for child in children:
                tg.create_task(SecureModel.async_post_init_nested(child))

    async def async_post_init(self) -> None:
        """Run async encrypt + hash + blind-index, including on nested models."""

        async with asyncio.TaskGroup() as tg:
            for name in getattr(type(self), "model_fields", {}):
                value = getattr(self, name, None)
                if value is not None:
                    tg.create_task(self.async_post_init_nested(value))
            tg.create_task(self.async_encrypt_data())
            tg.create_task(self.async_hash_data())
            tg.create_task(self.async_blind_index_data())


class BaseModel(SuperModelPydanticMixin, SecureModel):
    """Pydantic base model with automatic encryption, hashing, and blind indexing."""

    def model_post_init(self, context: Any, /) -> None:
        self.default_post_init()
        super().model_post_init(context)

    @classmethod
    async def async_init(cls, /, **data: Any) -> Self:
        """Construct a model with async encryption, hashing, and blind indexing."""

        token = defer_crypto_to_async.set(True)
        try:
            instance = cls(**data)
        finally:
            defer_crypto_to_async.reset(token)
        await instance.async_post_init()
        return instance
