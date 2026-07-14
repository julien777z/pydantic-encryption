import os
import shutil
from pathlib import Path

from agent_sync.models.outputs import OutputFile

__all__ = [
    "delete_path",
    "expected_link_text",
    "is_executable_output",
    "missing_exec_bit",
    "read_link",
    "read_text",
    "write_symlink",
    "write_text",
]


def read_text(path: Path) -> str | None:
    """Read UTF-8 text when a path exists."""

    return path.read_text(encoding="utf-8") if path.exists() else None


def write_text(path: Path, content: str) -> None:
    """Write generated text and apply executable permissions when required."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        path.unlink()
    path.write_text(content, encoding="utf-8")
    if is_executable_output(path, content):
        path.chmod(0o755)


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


def missing_exec_bit(output: OutputFile) -> bool:
    """Return whether executable output exists without an executable bit."""

    target = output.target_path

    return (
        is_executable_output(target, output.content) and target.exists() and not target.stat().st_mode & 0o111
    )
