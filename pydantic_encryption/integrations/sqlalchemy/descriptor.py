from typing import Any

from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

try:
    from sqlalchemy.util import await_  # type: ignore[attr-defined]
except ImportError:
    from sqlalchemy.util import await_only as await_

from sqlalchemy.exc import MissingGreenlet
from sqlalchemy.orm import object_session

from pydantic_encryption.integrations.sqlalchemy._state import pending_siblings
from pydantic_encryption.integrations.sqlalchemy.bulk import decrypt_rows
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
        if session is None:
            raise EncryptedValueAccessError(
                f"Cannot decrypt {self._cls.__name__}.{self._column_key} on a detached instance. "
                "Call `await instance.decrypt()` or `await decrypt_pending_fields(session)` first."
            )

        rows = {instance, *pending_siblings(session, self._cls)}
        try:
            await_(decrypt_rows(rows, self._column_key))
        except MissingGreenlet:
            raise EncryptedValueAccessError(
                f"Cannot decrypt {self._cls.__name__}.{self._column_key} outside of an "
                "async-session greenlet. Call `await decrypt_pending_fields(session)` or "
                "`await instance.decrypt()` first."
            )

        return self._wrapped.__get__(instance, owner)

    def __set__(self, instance: Any, value: Any) -> None:
        self._wrapped.__set__(instance, value)

    def __delete__(self, instance: Any) -> None:
        self._wrapped.__delete__(instance)


__all__ = ["DecryptOnAccessDescriptor"]
