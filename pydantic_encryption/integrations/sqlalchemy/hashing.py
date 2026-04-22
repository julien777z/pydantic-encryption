from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.types import LargeBinary, TypeDecorator

from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.types import HashedValue


class SQLAlchemyHashedValue(TypeDecorator):
    """SQLAlchemy column type that Argon2-hashes strings on write."""

    impl = LargeBinary
    cache_ok = True

    def _hash(self, value: str | bytes) -> HashedValue:
        return run_async_or_sync(Argon2Adapter.async_hash, Argon2Adapter.hash, value)

    def process_bind_param(self, value: str | bytes | None, dialect) -> bytes | None:
        """Hash a value before binding it to the database."""

        if value is None:
            return None

        return self._hash(value)

    def process_literal_param(self, value: str | bytes | None, dialect) -> HashedValue | None:
        """Hash a value for literal SQL expressions."""

        if value is None:
            return None

        return dialect.literal_processor(self.impl)(self._hash(value))

    def process_result_value(self, value: str | bytes | None, dialect) -> HashedValue | None:
        """Return the stored hash wrapped as a ``HashedValue``."""

        if value is None:
            return None

        return HashedValue(value)

    @property
    def python_type(self):
        """Return the Python type this column is bound to."""

        return self.impl.python_type
