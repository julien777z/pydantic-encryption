import importlib
from types import ModuleType


def require_optional_dependency(module_name: str, extra_name: str) -> ModuleType:
    """Import an optional dependency, raising a helpful error if not installed."""

    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        raise ImportError(
            f"Optional dependency '{module_name}' not installed. "
            f"Install with: pip install pydantic-encryption[{extra_name}]"
        ) from e
