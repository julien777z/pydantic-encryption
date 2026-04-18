from typing import Any

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.ext.asyncio import AsyncSession

from pydantic_encryption.integrations.sqlalchemy.bulk import (
    AUTO_DECRYPT_ENABLED_KEY,
    PENDING_DECRYPT_KEY,
)


class AutoDecryptAsyncSession(AsyncSession):
    """AsyncSession that batch-decrypts deferred DeferredDecryptMixin rows after each execute().

    Streaming queries (``stream``, ``stream_scalars``) bypass auto-decrypt — call
    ``Model.decrypt_many(batch)`` per chunk or materialize the result with ``.all()``.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.info[AUTO_DECRYPT_ENABLED_KEY] = True

    async def execute(self, statement, *args, **kwargs):
        """Run the query, then batch-decrypt every DeferredDecryptMixin row populated by it."""

        result = await super().execute(statement, *args, **kwargs)
        await self._drain_pending_decrypt()
        return result

    async def _drain_pending_decrypt(self) -> None:
        """Pop the per-session pending bucket and call decrypt_many per class."""

        pending: dict[type, list[Any]] | None = self.info.pop(PENDING_DECRYPT_KEY, None)
        if not pending:
            return
        for cls, instances in pending.items():
            await cls.decrypt_many(instances)


__all__ = ["AutoDecryptAsyncSession"]
