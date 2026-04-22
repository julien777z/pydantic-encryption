from typing import Any

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.orm import object_session

from pydantic_encryption.config import settings
from pydantic_encryption.integrations.sqlalchemy._async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy._state import pending_siblings
from pydantic_encryption.integrations.sqlalchemy.bulk import (
    _decrypt_rows_sync,
    async_decrypt_rows,
)
from pydantic_encryption.types import EncryptedValue, EncryptedValueAccessError


class DecryptOnAccessDescriptor:
    """Descriptor that batch-decrypts one column across session siblings on first read."""

    __slots__ = ("_wrapped", "_cls", "_column_key")

    def __init__(self, wrapped: Any, cls: type, column_key: str) -> None:
        self._wrapped = wrapped
        self._cls = cls
        self._column_key = column_key

    @property
    def key(self) -> str:
        """Column key of the wrapped InstrumentedAttribute."""

        return self._wrapped.key

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self._wrapped

        value = self._wrapped.__get__(instance, owner)
        if not isinstance(value, EncryptedValue):
            return value

        session = object_session(instance)
        if session is None and settings.DECRYPT_STRICT_DETACHED:
            raise EncryptedValueAccessError(
                f"Cannot decrypt {self._cls.__name__}.{self._column_key} on a detached instance "
                "while DECRYPT_STRICT_DETACHED is enabled. Call `await instance.decrypt()` or "
                "`await decrypt_pending_fields(session)` before passing rows across async boundaries."
            )

        rows = {instance, *pending_siblings(session, self._cls)}
        run_async_or_sync(
            async_decrypt_rows,
            _decrypt_rows_sync,
            rows,
            self._column_key,
        )

        return self._wrapped.__get__(instance, owner)

    def __set__(self, instance: Any, value: Any) -> None:
        self._wrapped.__set__(instance, value)

    def __delete__(self, instance: Any) -> None:
        self._wrapped.__delete__(instance)


__all__ = ["DecryptOnAccessDescriptor"]
