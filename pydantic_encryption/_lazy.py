import importlib
from types import ModuleType
from typing import Optional


class LazyModule:
    """Lazy module loader that defers import until first attribute access."""

    def __init__(self, module_name: str, package: Optional[str] = None, required_extra: Optional[str] = None):
        self._module_name = module_name
        self._package = package
        self._required_extra = required_extra
        self._module: Optional[ModuleType] = None

    def _load(self) -> None:
        try:
            self._module = importlib.import_module(self._module_name, self._package)
        except ImportError as e:
            if self._required_extra:
                raise ImportError(
                    f"Optional dependency not installed. "
                    f"Install with: pip install pydantic-encryption[{self._required_extra}]"
                ) from e
            raise

    def __getattr__(self, name: str):
        if self._module is None:
            self._load()

        return getattr(self._module, name)

    def __repr__(self) -> str:
        return f"<LazyModule({self._module_name!r})>"


def require_optional_dependency(module_name: str, extra_name: str) -> ModuleType:
    """Import an optional dependency, raising a helpful error if not installed."""

    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        raise ImportError(
            f"Optional dependency '{module_name}' not installed. "
            f"Install with: pip install pydantic-encryption[{extra_name}]"
        ) from e
