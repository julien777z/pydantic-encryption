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
    """AsyncSession flagged for on-access decrypt with an explicit drain escape hatch."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.info[AUTO_DECRYPT_ENABLED_KEY] = True

    async def drain_pending_decrypt(self) -> None:
        """Force-decrypt every encrypted column on every instance in the pending bucket."""

        pending: dict[type, list[Any]] | None = self.info.pop(PENDING_DECRYPT_KEY, None)
        if not pending:
            return
        all_instances = [instance for instances in pending.values() for instance in instances]
        await _bulk_decrypt(all_instances)


__all__ = ["AutoDecryptAsyncSession"]
