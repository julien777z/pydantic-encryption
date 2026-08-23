from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Self
from weakref import WeakSet

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import event

from pydantic_encryption.integrations.sqlalchemy.bulk import bulk_decrypt_entities
from pydantic_encryption.integrations.sqlalchemy.encryption import DeferrableEncryptedType
from pydantic_encryption.integrations.sqlalchemy.state import PENDING_DECRYPT_KEY


def defer_encrypted_columns(mapper: Any, class_: type) -> None:
    """Mark every encrypted column deferred so its value decrypts in the batched drain."""

    for column in mapper.columns:
        if not isinstance(column.type, DeferrableEncryptedType):
            continue

        if not column.type.deferred:
            # Copy so we don't mutate a TypeDecorator instance shared across mappers.
            column.type = column.type.copy()
            column.type.deferred = True


def on_orm_load(instance: Any, context: Any) -> None:
    """Add a freshly loaded instance to the session's pending-decrypt bucket."""

    if context is None:
        return

    session = context.session
    if session is None:
        return

    bucket: dict[type, WeakSet] = session.info.setdefault(PENDING_DECRYPT_KEY, defaultdict(WeakSet))
    bucket[type(instance)].add(instance)


def on_orm_refresh(instance: Any, context: Any, attrs: Any) -> None:
    """Re-add a refreshed instance to the session's pending-decrypt bucket."""

    on_orm_load(instance, context)


class DeferredDecryptMixin:
    """Defer encrypted-column decryption until the session's pending batch is drained."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", defer_encrypted_columns)
        event.listen(cls, "load", on_orm_load)
        event.listen(cls, "refresh", on_orm_refresh)

    async def decrypt(self) -> Self:
        """Decrypt every deferred encrypted column on this instance and loaded relationships."""

        await bulk_decrypt_entities(self)

        return self

    @classmethod
    async def decrypt_many(cls, entities: Any | Iterable[Any] | None) -> None:
        """Decrypt every deferred encrypted column on the given entities and loaded relationships."""

        await bulk_decrypt_entities(entities)


__all__ = ["DeferredDecryptMixin", "defer_encrypted_columns", "on_orm_load", "on_orm_refresh"]
