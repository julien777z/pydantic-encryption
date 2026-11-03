from collections.abc import Sequence
from typing import Self, overload

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy import Column, Table, util
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.engine import Dialect
from sqlalchemy.sql.base import SchemaEventTarget
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.types import ARRAY, TypeEngine

from pydantic_encryption.adapters.base import encode_text
from pydantic_encryption.adapters.registry import configured_encryption_backend
from pydantic_encryption.context import append_row_key, derive_column_context
from pydantic_encryption.integrations.sqlalchemy.async_bridge import run_async_or_sync
from pydantic_encryption.integrations.sqlalchemy.binary import BinaryColumnType, BinaryStorage, ColumnValueT
from pydantic_encryption.integrations.sqlalchemy.state import row_key
from pydantic_encryption.serialization import (
    EncryptableValue,
    decode_value,
    encode_value,
)
from pydantic_encryption.types import EncryptedValue


class ContextBoundType(BinaryColumnType[ColumnValueT]):
    """Column type that binds its ciphertexts to the table and column it is attached to."""

    def __init__(self, context: str | bytes | None = None, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.declared_context: bytes | None = encode_text(context) if context is not None else None
        self.context: bytes | None = self.declared_context
        self.bound_column: str | None = None

    def _set_parent(self, parent: SchemaEventTarget, outer: bool = False, **kw: object) -> None:
        """Wait for the column this type is attached to to join its table."""

        super()._set_parent(parent, outer=outer, **kw)

        assert isinstance(parent, Column)
        parent._on_table_attach(util.portable_instancemethod(self.bind_table))

    def bind_table(self, column: Column[ColumnValueT], table: Table) -> None:
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
        """Return the context every cell of this column binds its ciphertext to."""

        return self.column_context()

    def context_for(self, row: object) -> bytes:
        """Return the context the given row's cell in this column binds its ciphertext to."""

        return self.bound_context()


class SQLAlchemyEncryptedValue(ContextBoundType[EncryptableValue]):
    """SQLAlchemy column type that encrypts on write and decrypts on read, binding cells to ``context``."""

    cache_ok: bool | None = True
    deferred: bool = False

    def __init__(
        self, context: str | bytes | None = None, row_bound: bool = False, *args: object, **kwargs: object
    ) -> None:
        super().__init__(context, *args, **kwargs)
        self.row_bound: bool = row_bound

    def bound_context(self) -> bytes:
        """Return the context every cell of this column binds to, refusing where each row binds its own."""

        if self.row_bound:
            raise ValueError(
                "This column binds each row separately, and no row is in scope here. "
                "Mix DeferredDecryptMixin into the mapped class so reads and writes carry the row."
            )

        return super().bound_context()

    def cell_context(self, *row_key: str) -> bytes:
        """Return the context the named row's cell in this column binds its ciphertext to."""

        return append_row_key(self.column_context(), *row_key)

    def context_for(self, row: object) -> bytes:
        """Return the context the given row's cell binds to: its own row's where the column is row-bound."""

        if self.row_bound:
            return self.cell_context(*row_key(sa_inspect(type(row), raiseerr=True), row))

        return self.bound_context()

    @overload
    def encrypt_cell(self, value: None, *, context: bytes | None = None) -> None: ...

    @overload
    def encrypt_cell(self, value: EncryptableValue, *, context: bytes | None = None) -> EncryptedValue: ...

    def encrypt_cell(
        self, value: EncryptableValue | None, *, context: bytes | None = None
    ) -> EncryptedValue | None:
        """Encode + encrypt a single value, passing pre-encrypted values through."""

        if value is None:
            return None
        if isinstance(value, EncryptedValue):
            return value

        backend = configured_encryption_backend()

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

        backend = configured_encryption_backend()

        return run_async_or_sync(
            backend.async_decrypt,
            backend.decrypt,
            value,
            associated_data=context if context is not None else self.bound_context(),
        )

    def process_bind_param(self, value: EncryptableValue | None, dialect: Dialect) -> bytes | None:
        """Encrypt a value before binding it to the database."""

        return self.encrypt_cell(value)

    def process_result_value(self, value: str | bytes | None, dialect: Dialect) -> EncryptableValue | None:
        """Decrypt a value after retrieving it from the database."""

        if value is None:
            return None

        if self.deferred:
            return EncryptedValue(value)

        return decode_value(self.decrypt_cell(value))


class SQLAlchemyPGEncryptedArray(ContextBoundType[list[EncryptableValue | None]]):
    """SQLAlchemy column type that encrypts each element of a PostgreSQL array under ``context``."""

    cache_ok: bool | None = True
    impl: TypeEngine[Sequence[bytes]] | type[TypeEngine[Sequence[bytes]]] = ARRAY(BinaryStorage())

    def __init__(self, context: str | bytes | None = None) -> None:
        super().__init__(context)
        self.element_type: SQLAlchemyEncryptedValue = SQLAlchemyEncryptedValue(context)

    def bind_table(self, column: Column[list[EncryptableValue | None]], table: Table) -> None:
        """Bind every element of this array to the context the column itself is bound to."""

        super().bind_table(column, table)
        self.element_type.context = self.context

    def copy(self, **kw: object) -> Self:
        """Copy this type with an element type of its own, so each column derives its own context."""

        duplicate = super().copy(**kw)
        duplicate.element_type = self.element_type.copy()

        return duplicate

    def process_bind_param(
        self, value: list[EncryptableValue | None] | None, dialect: Dialect
    ) -> list[EncryptedValue | None] | None:
        """Encrypt each element before binding to the database."""

        if value is None:
            return None

        return [self.element_type.encrypt_cell(element) for element in value]

    def process_result_value(
        self, value: list[bytes | None] | None, dialect: Dialect
    ) -> list[EncryptableValue | None] | None:
        """Decrypt each element after retrieving the array from the database."""

        if value is None:
            return None

        return [
            None if element is None else decode_value(self.element_type.decrypt_cell(element))
            for element in value
        ]


def encrypted_column_type(column: ColumnElement[object]) -> ContextBoundType[object]:
    """Return the encrypted type of a column, refusing a column that does not encrypt its values."""

    column_type = column.type

    if not isinstance(column_type, ContextBoundType):
        raise ValueError(f"Column {column.key!r} does not encrypt its values, so it binds no context.")

    return column_type
