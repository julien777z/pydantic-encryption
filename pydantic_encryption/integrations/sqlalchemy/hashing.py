from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.engine import Dialect

from pydantic_encryption.adapters.hashing.argon2 import Argon2Adapter
from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.binary import BinaryColumnType
from pydantic_encryption.types import HashedValue


class SQLAlchemyHashedValue(BinaryColumnType[str | bytes]):
    """SQLAlchemy column type that Argon2-hashes strings on write."""

    cache_ok: bool | None = True

    def hash(self, value: str | bytes) -> HashedValue:
        """Hash a value with Argon2, through the greenlet bridge when one is running."""

        return run_async_or_sync(Argon2Adapter.async_hash, Argon2Adapter.hash, value)

    def process_bind_param(self, value: str | bytes | None, dialect: Dialect) -> bytes | None:
        """Hash a value before binding it to the database."""

        if value is None:
            return None

        return self.hash(value)

    def process_result_value(self, value: str | bytes | None, dialect: Dialect) -> HashedValue | None:
        """Return the stored hash wrapped as a ``HashedValue``."""

        if value is None:
            return None

        return HashedValue(value)
