import os
import shutil
from pathlib import Path

from agent_sync.models.outputs import OutputFile

__all__ = [
    "delete_path",
    "expected_link_text",
    "has_incorrect_exec_bit",
    "is_executable_output",
    "read_link",
    "read_text",
    "write_symlink",
    "write_text",
]


def read_text(path: Path, *, root: Path | None = None) -> str | None:
    """Read UTF-8 text when a path exists."""

    if path.is_symlink() or has_symlink_ancestor(path, root) or not path.is_file():
        return None

    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    """Write generated text and apply executable permissions when required."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755 if is_executable_output(path, content) else 0o644)


def write_symlink(path: Path, target: Path) -> None:
    """Replace a path with a relative symlink to its canonical source."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        delete_path(path)
    path.symlink_to(os.path.relpath(target, path.parent))


def read_link(path: Path) -> str | None:
    """Return a symlink target or None for a non-symlink path."""

    return os.readlink(path) if path.is_symlink() else None


def delete_path(path: Path) -> None:
    """Delete a file, directory, or symlink."""

    if path.is_symlink():
        path.unlink()

        return

    if not path.exists():
        return

    if path.is_dir():
        shutil.rmtree(path)

        return

    path.unlink()


def expected_link_text(output: OutputFile) -> str:
    """Return the relative symlink target for one generated output."""

    if output.link_target is None:
        raise ValueError(f"Output is not a symlink: {output.target_path}")

    return os.path.relpath(output.link_target, output.target_path.parent)


def is_executable_output(path: Path, content: str) -> bool:
    """Return whether generated output should carry an executable bit."""

    return path.suffix == ".sh" or content.startswith("#!")


def has_incorrect_exec_bit(output: OutputFile, *, root: Path | None = None) -> bool:
    """Return whether an output's executable state differs from the manifest."""

    target = output.target_path

    if target.is_symlink() or has_symlink_ancestor(target, root) or not target.is_file():
        return False

    is_executable = bool(target.stat().st_mode & 0o111)

    return is_executable != is_executable_output(target, output.content)


def has_symlink_ancestor(path: Path, root: Path | None) -> bool:
    """Return whether resolving a path would traverse a symlinked directory."""

    if root is None:
        return False

    parent = path.parent
    while parent != root:
        if parent.is_symlink():
            return True

        if parent == parent.parent:
            return False

        parent = parent.parent

    return root.is_symlink()
