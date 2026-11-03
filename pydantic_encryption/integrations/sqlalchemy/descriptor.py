from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.orm import InstrumentedAttribute, object_session

from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.bulk import open_rows, open_rows_sync
from pydantic_encryption.integrations.sqlalchemy.state import drop_pending, pending_siblings
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
        """Return the column's value, batch-decrypting it across session siblings on first read.

        A row whose cell fails to open stays sealed, leaves the session's batch, and raises only when it
        is read itself.
        """

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

        failures = run_async_or_sync(open_rows, open_rows_sync, rows, self._column_key)

        if session is not None:
            drop_pending(session, self._cls, (row for row, _ in failures))

        for row, error in failures:
            if row is instance:
                raise error

        return self._wrapped.__get__(instance, owner)

    def __set__(self, instance: object, value: object) -> None:
        """Assign the column's value through the wrapped attribute."""

        self._wrapped.__set__(instance, value)

    def __delete__(self, instance: object) -> None:
        """Delete the column's value through the wrapped attribute."""

        self._wrapped.__delete__(instance)


__all__ = ["DecryptOnAccessDescriptor"]
