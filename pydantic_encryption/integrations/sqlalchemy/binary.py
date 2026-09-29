from typing import Final, Protocol

from pydantic_encryption.lazy import require_optional_dependency

require_optional_dependency("sqlalchemy", "sqlalchemy")

from sqlalchemy.engine import Dialect
from sqlalchemy.exc import CompileError
from sqlalchemy.types import LargeBinary, TypeDecorator, TypeEngine

BINARY_LITERAL_TEMPLATES: Final[dict[str, str]] = {
    "postgresql": "decode('{hex}', 'hex')",
    "sqlite": "X'{hex}'",
    "mysql": "X'{hex}'",
    "mariadb": "X'{hex}'",
    "mssql": "0x{hex}",
    "oracle": "HEXTORAW('{hex}')",
}


class BinaryLiteralRenderer(Protocol):
    """Renderer of one stored value as SQL literal text."""

    def __call__(self, value: bytes | None) -> str: ...


class BinaryStorage(TypeDecorator[bytes]):
    """Binary column storage that renders a literal value in its dialect's binary literal syntax."""

    impl: TypeEngine[bytes] | type[TypeEngine[bytes]] = LargeBinary
    cache_ok: bool | None = True

    def literal_processor(self, dialect: Dialect) -> BinaryLiteralRenderer:
        """Return a renderer of bytes as the dialect's binary literal."""

        template = BINARY_LITERAL_TEMPLATES.get(dialect.name)
        if template is None:
            raise CompileError(f"No binary literal syntax is known for the {dialect.name} dialect.")

        def render(value: bytes | None) -> str:
            """Render one value as a binary literal, or NULL."""

            if value is None:
                return "NULL"

            return template.format(hex=value.hex())

        return render

    @property
    def python_type(self) -> type[bytes]:
        """Return the Python type this storage holds."""

        return self.impl_instance.python_type


__all__ = ["BinaryStorage"]
