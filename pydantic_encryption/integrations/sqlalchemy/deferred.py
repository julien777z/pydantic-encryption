from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Self
from weakref import WeakSet

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import event

from pydantic_encryption.integrations.sqlalchemy._state import PENDING_DECRYPT_KEY
from pydantic_encryption.integrations.sqlalchemy.bulk import bulk_decrypt_entities
from pydantic_encryption.integrations.sqlalchemy.descriptor import DecryptOnAccessDescriptor
from pydantic_encryption.integrations.sqlalchemy.encryption import SQLAlchemyEncryptedValue


def install_descriptors(mapper: Any, class_: type) -> None:
    """Mark encrypted columns deferred and wrap their class attrs with the on-access descriptor."""

    for column in mapper.columns:
        if not isinstance(column.type, SQLAlchemyEncryptedValue):
            continue

        if not column.type._deferred:
            # Copy so we don't mutate a TypeDecorator instance shared across mappers.
            column.type = column.type.copy()
            column.type._deferred = True

        column_key = column.key
        existing = class_.__dict__.get(column_key)
        if isinstance(existing, DecryptOnAccessDescriptor):
            continue

        wrapped = getattr(class_, column_key, None)
        if wrapped is None:
            continue

        try:
            setattr(class_, column_key, DecryptOnAccessDescriptor(wrapped, class_, column_key))
        except (AttributeError, TypeError):
            continue


def on_orm_load(instance: Any, context: Any) -> None:
    """Add a freshly loaded instance to the session's pending-decrypt bucket."""

    if context is None:
        return

    session = context.session
    if session is None:
        return

    bucket: dict[type, WeakSet] = session.info.setdefault(
        PENDING_DECRYPT_KEY, defaultdict(WeakSet)
    )
    bucket[type(instance)].add(instance)


def on_orm_refresh(instance: Any, context: Any, attrs: Any) -> None:
    """Re-add a refreshed instance to the session's pending-decrypt bucket."""

    on_orm_load(instance, context)


class DeferredDecryptMixin:
    """Defer encrypted-column decryption until first attribute access, batched per column."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        event.listen(cls, "mapper_configured", install_descriptors)
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


__all__ = ["DeferredDecryptMixin", "install_descriptors", "on_orm_load", "on_orm_refresh"]
