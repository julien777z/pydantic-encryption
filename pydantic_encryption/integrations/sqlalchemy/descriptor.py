from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.orm import InstrumentedAttribute, object_session

from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.state import pending_siblings
from pydantic_encryption.integrations.sqlalchemy.bulk import decrypt_rows, decrypt_rows_sync
from pydantic_encryption.types import EncryptedValue


class DecryptOnAccessDescriptor:
    """Descriptor that batch-decrypts one column across session siblings on first read."""

    __slots__ = ("_wrapped", "_cls", "_column_key")

    def __init__(self, wrapped: InstrumentedAttribute[object], cls: type[object], column_key: str) -> None:
        self._wrapped = wrapped
        self._cls = cls
        self._column_key = column_key

    @property
    def key(self) -> str:
        """Column key of the wrapped InstrumentedAttribute."""

        return self._wrapped.key

    def __get__(self, instance: object | None, owner: type[object] | None = None) -> object:
        """Return the column's value, batch-decrypting it across session siblings on first read."""

        if instance is None:
            return self._wrapped

        value = self._wrapped.__get__(instance, owner)
        if not isinstance(value, EncryptedValue):
            return value

        session = object_session(instance)
        if session is None:
            rows: list[object] | set[object] = [instance]
        else:
            rows = {instance, *pending_siblings(session, self._cls)}

        run_async_or_sync(decrypt_rows, decrypt_rows_sync, rows, self._column_key)

        return self._wrapped.__get__(instance, owner)

    def __set__(self, instance: object, value: object) -> None:
        """Assign the column's value through the wrapped attribute."""

        self._wrapped.__set__(instance, value)

    def __delete__(self, instance: object) -> None:
        """Delete the column's value through the wrapped attribute."""

        self._wrapped.__delete__(instance)


__all__ = ["DecryptOnAccessDescriptor"]
