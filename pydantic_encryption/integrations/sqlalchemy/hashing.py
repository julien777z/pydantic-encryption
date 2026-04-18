from pydantic_encryption._lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters import hashing
from pydantic_encryption.integrations.sqlalchemy._async_bridge import _SENTINEL, try_await
from pydantic_encryption.types import HashedValue


class SQLAlchemyHashedValue(TypeDecorator):
    """Type adapter for SQLAlchemy to hash strings using Argon2.

    Argon2 is memory-hard (tens of ms per call). Under ``AsyncSession``, hashing
    uses SQLAlchemy's greenlet bridge so the event loop isn't blocked during
    ``commit()``. Falls back to the blocking path for plain sync ``Session``.
    """

    impl = LargeBinary
    cache_ok = True

    def _hash(self, value: str | bytes) -> HashedValue:
        result = try_await(hashing.argon2.Argon2Adapter.async_hash(value))
        if result is _SENTINEL:
            return hashing.argon2.Argon2Adapter.hash(value)
        return result

    def process_bind_param(self, value: str | bytes | None, dialect) -> bytes | None:
        """Hashes a string before binding it to the database."""

        if value is None:
            return None

        return self._hash(value)

    def process_literal_param(self, value: str | bytes | None, dialect) -> HashedValue | None:
        """Hashes a string for literal SQL expressions."""

        if value is None:
            return None

        return dialect.literal_processor(self.impl)(self._hash(value))

    def process_result_value(self, value: str | bytes | None, dialect) -> HashedValue | None:
        """Returns the hash value as-is from the database, wrapped as a HashedValue."""

        if value is None:
            return None

        return HashedValue(value)

    @property
    def python_type(self):
        """Return the Python type this is bound to (str)."""

        return self.impl.python_type
