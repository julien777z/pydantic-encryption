from typing import Any

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.ext.asyncio import AsyncSession

from pydantic_encryption.integrations.sqlalchemy.bulk import (
    AUTO_DECRYPT_ENABLED_KEY,
    PENDING_DECRYPT_KEY,
    _bulk_decrypt,
)


class AutoDecryptAsyncSession(AsyncSession):
    """AsyncSession that defers decryption of ``DeferredDecryptMixin`` columns until first access.

    Historically this class eagerly drained every encrypted column after each
    ``execute()`` / ``get()`` / ``refresh()`` / ``merge()``. That wasted KMS
    round-trips on columns the response never reads. Decryption is now driven
    by the on-access descriptor installed via :class:`DeferredDecryptMixin`:
    reading ``instance.<encrypted_col>`` batch-decrypts that column across all
    sibling instances loaded into the same session.

    The class is preserved so existing ``async_sessionmaker(class_=...)``
    wiring keeps working. ``drain_pending_decrypt()`` is still available for
    callers that want to pre-warm every encrypted column before leaving the
    session context.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.info[AUTO_DECRYPT_ENABLED_KEY] = True

    async def drain_pending_decrypt(self) -> None:
        """Decrypt every encrypted column on every instance currently in the session bucket.

        Optional escape hatch for callers that need plaintext on every column
        before leaving the async context (e.g. serializing outside a greenlet
        spawn). Normal request flow does not need to call this.
        """

        pending: dict[type, list[Any]] | None = self.info.pop(PENDING_DECRYPT_KEY, None)
        if not pending:
            return
        all_instances = [instance for instances in pending.values() for instance in instances]
        await _bulk_decrypt(all_instances)


__all__ = ["AutoDecryptAsyncSession"]
