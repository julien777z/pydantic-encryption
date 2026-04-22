from typing import Any

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.ext.asyncio import AsyncSession

from pydantic_encryption.integrations.sqlalchemy.bulk import (
    PENDING_DECRYPT_KEY,
    _bulk_decrypt,
)


class AutoDecryptAsyncSession(AsyncSession):
    """AsyncSession subclass preserved for wiring compatibility; exposes an explicit drain helper."""

    async def drain_pending_decrypt(self) -> None:
        """Force-decrypt every encrypted column on every instance in the pending bucket."""

        pending: dict[type, list[Any]] | None = self.info.pop(PENDING_DECRYPT_KEY, None)
        if not pending:
            return
        all_instances = [instance for instances in pending.values() for instance in instances]
        await _bulk_decrypt(all_instances)


__all__ = ["AutoDecryptAsyncSession"]
