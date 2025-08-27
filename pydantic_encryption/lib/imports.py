import importlib


def optional_import(module_name: str, __all__: list[str] | None = None) -> object | None:
    """Safely import a module with optional ``__all__`` management.

    Args:
        module_name: Relative module path to import (e.g., ``'.encryption.fernet'``).
        __all__: Optional list to append successful import names to.

    Returns:
        The imported module if successful, otherwise ``None`` when ImportError occurs.
    """

    try:
        module = importlib.import_module(module_name, __package__)

        if __all__ is not None:
            __all__.append(module_name.rsplit(".", 1)[-1])

        return module

    except ImportError:
        return None


def import_submodules(
    package_name: str,
    submodule_names: list[str],
    __all__: list[str] | None = None,
) -> dict[str, object | None]:
    """Import multiple submodules with automatic ``__all__`` management.

    Args:
        package_name: Package containing the submodules (e.g., ``'.encryption'``).
        submodule_names: Submodule names to import from the package.
        __all__: Optional list to append successful import names to.

    Returns:
        Mapping of submodule name to the imported module (or ``None`` if not available).
    """

    modules: dict[str, object | None] = {}

    for name in submodule_names:
        module_path = f"{package_name}.{name}"
        modules[name] = optional_import(module_path, __all__)

    return modules


__all__ = ["optional_import", "import_submodules"]
