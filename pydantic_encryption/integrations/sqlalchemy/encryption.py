from collections.abc import Sequence
from typing import Self, TypeVar, overload

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import Column, Table, util
from sqlalchemy.engine import Dialect
from sqlalchemy.sql.base import SchemaEventTarget
from sqlalchemy.types import ARRAY, LargeBinary, TypeDecorator, TypeEngine

from pydantic_encryption.adapters.base import EncryptionAdapter, encode_text
from pydantic_encryption.adapters.registry import get_encryption_backend
from pydantic_encryption.config import settings
from pydantic_encryption.context import append_row_key, derive_column_context
from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.serialization import (
    EncryptableValue,
    decode_value,
    encode_value,
)
from pydantic_encryption.types import EncryptedValue

ColumnValueT = TypeVar("ColumnValueT")


class ContextBoundType(TypeDecorator[ColumnValueT]):
    """Column type that binds its ciphertexts to the table and column it is attached to."""

    def __init__(
        self, context: str | bytes | None = None, row_bound: bool = False, *args: object, **kwargs: object
    ) -> None:
        super().__init__(*args, **kwargs)
        self.declared_context: bytes | None = encode_text(context) if context is not None else None
        self.context: bytes | None = self.declared_context
        self.row_bound: bool = row_bound
        self.bound_column: str | None = None

    def _set_parent(self, parent: SchemaEventTarget, outer: bool = False, **kw: object) -> None:
        """Wait for the column this type is attached to to join its table."""

        super()._set_parent(parent, outer=outer, **kw)

        assert isinstance(parent, Column)
        parent._on_table_attach(util.portable_instancemethod(self._set_table))

    def _set_table(self, column: Column[ColumnValueT], table: Table) -> None:
        """Derive the context from the column this type is attached to, unless one was declared."""

        attached = f"{table.fullname}.{column.name}"
        if self.bound_column is not None and self.bound_column != attached:
            raise ValueError(
                f"This encrypted type is already bound to {self.bound_column}, and one type binds one "
                f"column: attaching it to {attached} as well would rebind what {self.bound_column} "
                "already wrote. Give each column a type of its own."
            )

        self.bound_column = attached
        if self.declared_context is None:
            self.context = derive_column_context(table.name, column.name, schema=table.schema)
            self.__dict__.pop("_static_cache_key", None)

    def copy(self, **kw: object) -> Self:
        """Copy this type unbound, so the column it lands on derives a context of its own."""

        duplicate = super().copy(**kw)
        duplicate.bound_column = None
        duplicate.__dict__.pop("_static_cache_key", None)

        return duplicate

    def column_context(self) -> bytes:
        """Return the context naming the column itself, which a row-bound cell extends."""

        if self.context is None:
            raise ValueError(
                "This encrypted type is attached to no column, so it can derive no context. "
                "Pass one explicitly to bind its ciphertexts."
            )

        return self.context

    def bound_context(self) -> bytes:
        """Return the context a cell of this column binds its ciphertext to."""

        if self.row_bound:
            raise ValueError(
                "This column binds each row separately, and no row is in scope here. "
                "Mix DeferredDecryptMixin into the mapped class so reads and writes carry the row."
            )

        return self.column_context()

    def cell_context(self, *row_key: str) -> bytes:
        """Return the context the named row's cell in this column binds its ciphertext to."""

        return append_row_key(self.column_context(), *row_key)


class SQLAlchemyEncryptedValue(ContextBoundType[EncryptableValue]):
    """SQLAlchemy column type that encrypts on write and decrypts on read, binding cells to ``context``."""

    impl: TypeEngine[bytes] | type[TypeEngine[bytes]] = LargeBinary
    cache_ok: bool | None = True
    _deferred: bool = False

    @staticmethod
    def backend() -> type[EncryptionAdapter]:
        """Return the configured encryption backend, raising if ENCRYPTION_METHOD is unset."""

        if settings.ENCRYPTION_METHOD is None:
            raise ValueError("ENCRYPTION_METHOD must be set to use SQLAlchemyEncryptedValue.")

        return get_encryption_backend(settings.ENCRYPTION_METHOD)

    def encrypt_cell(self, value: object, *, context: bytes | None = None) -> EncryptedValue | None:
        """Encode + encrypt a single value, passing pre-encrypted values through."""

        if value is None:
            return None
        if isinstance(value, EncryptedValue):
            return value

        backend = self.backend()

        return run_async_or_sync(
            backend.async_encrypt,
            backend.encrypt,
            encode_value(value),
            associated_data=context if context is not None else self.bound_context(),
        )

    @overload
    def decrypt_cell(self, value: str | bytes, *, context: bytes | None = None) -> str: ...

    @overload
    def decrypt_cell(self, value: None, *, context: bytes | None = None) -> None: ...

    def decrypt_cell(self, value: str | bytes | None, *, context: bytes | None = None) -> str | None:
        """Decrypt a single ciphertext; callers are responsible for decoding."""

        if value is None:
            return None

        backend = self.backend()

        return run_async_or_sync(
            backend.async_decrypt,
            backend.decrypt,
            value,
            associated_data=context if context is not None else self.bound_context(),
        )

    def process_bind_param(self, value: EncryptableValue | None, dialect: Dialect) -> bytes | None:
        """Encrypt a value before binding it to the database."""

        return self.encrypt_cell(value)

    def process_literal_param(self, value: EncryptableValue | None, dialect: Dialect) -> bytes | None:
        """Encrypt a value for literal SQL expressions."""

        return self.encrypt_cell(value)

    def process_result_value(self, value: str | bytes | None, dialect: Dialect) -> EncryptableValue | None:
        """Decrypt a value after retrieving it from the database."""

        if value is None:
            return None

        if self._deferred:
            return EncryptedValue(value)

        return decode_value(self.decrypt_cell(value))

    @property
    def python_type(self) -> type[bytes]:
        """Return the Python type this column is bound to."""

        return self.impl_instance.python_type


class SQLAlchemyPGEncryptedArray(ContextBoundType[list[EncryptableValue | None]]):
    """SQLAlchemy column type that encrypts each element of a PostgreSQL array under ``context``."""

    impl: TypeEngine[Sequence[bytes]] | type[TypeEngine[Sequence[bytes]]] = ARRAY(LargeBinary)
    cache_ok: bool | None = True

    def __init__(
        self, context: str | bytes | None = None, row_bound: bool = False, *args: object, **kwargs: object
    ) -> None:
        super().__init__(context, row_bound, *args, **kwargs)
        self._element_type: SQLAlchemyEncryptedValue = SQLAlchemyEncryptedValue(context)

        if self.row_bound:
            raise ValueError(
                "An encrypted array cannot bind its elements to a row: its cells decrypt on the "
                "read path, where no row is in scope."
            )

    def _set_table(self, column: Column[list[EncryptableValue | None]], table: Table) -> None:
        """Bind every element of this array to the context the column itself is bound to."""

        super()._set_table(column, table)
        self._element_type.context = self.context

    def copy(self, **kw: object) -> Self:
        """Copy this type with an element type of its own, so each column derives its own context."""

        duplicate = super().copy(**kw)
        duplicate._element_type = self._element_type.copy()

        return duplicate

    def process_bind_param(
        self, value: list[EncryptableValue | None] | None, dialect: Dialect
    ) -> list[EncryptedValue | None] | None:
        """Encrypt each element before binding to the database."""

        if value is None:
            return None

        return [self._element_type.encrypt_cell(element) for element in value]

    def process_literal_param(
        self, value: list[EncryptableValue | None] | None, dialect: Dialect
    ) -> list[EncryptedValue | None] | None:
        """Encrypt each element for literal SQL expressions."""

        if value is None:
            return None

        return [self._element_type.encrypt_cell(element) for element in value]

    def process_result_value(
        self, value: list[bytes | None] | None, dialect: Dialect
    ) -> list[EncryptableValue | None] | None:
        """Decrypt each element after retrieving the array from the database."""

        if value is None:
            return None

        return [
            None if element is None else decode_value(self._element_type.decrypt_cell(element))
            for element in value
        ]

    @property
    def python_type(self) -> type[list[EncryptableValue | None]]:
        """Return the Python type this column is bound to."""

        return list
