import difflib
import logging
from pathlib import Path
from typing import Final

from agent_sync.models.outputs import DiffEntry, OutputFile
from agent_sync.models.workspace import Workspace
from agent_sync.storage import (
    delete_path,
    expected_link_text,
    has_incorrect_exec_bit,
    read_link,
    read_text,
    write_symlink,
    write_text,
)

__all__ = ["apply_changes", "compute_diffs", "compute_stale_paths", "report_diffs"]

logger = logging.getLogger(__name__)

MAX_DIFF_LINES: Final[int] = 20
MANAGED_ROOT_NAMES: Final[tuple[str, ...]] = (".claude", ".cursor", ".codex")
MANAGED_ROOT_FILES: Final[tuple[str, ...]] = ("AGENTS.md", "AGENTS.override.md")


def compute_diffs(workspace: Workspace, outputs: list[OutputFile]) -> list[DiffEntry]:
    """Compare generated outputs with their on-disk state."""

    diffs: list[DiffEntry] = []
    for output in outputs:
        if output.link_target is not None:
            existing = read_link(output.target_path)

            if existing != expected_link_text(output):
                diffs.append(DiffEntry(output=output, existing=existing))
            continue

        existing = read_text(output.target_path, root=workspace.root)

        if (
            existing is None
            or existing != output.content
            or has_incorrect_exec_bit(output, root=workspace.root)
        ):
            diffs.append(DiffEntry(output=output, existing=existing))

    return diffs


def compute_stale_paths(workspace: Workspace, outputs: list[OutputFile]) -> list[Path]:
    """Find every managed path absent from the generated output manifest."""

    expected_outputs = {output.target_path: output for output in outputs}
    expected_paths = set(expected_outputs)
    managed_roots = tuple(workspace.root / name for name in MANAGED_ROOT_NAMES)
    expected_directories = build_expected_directories(managed_roots, expected_paths)
    stale_paths: set[Path] = set()

    for managed_root in managed_roots:
        stale_paths.update(
            find_stale_paths(
                managed_root,
                expected_outputs,
                expected_directories,
            )
        )

    for filename in MANAGED_ROOT_FILES:
        managed_file = workspace.root / filename

        if managed_file in expected_outputs:
            if managed_file.is_symlink() or managed_file.is_dir():
                stale_paths.add(managed_file)

            continue

        if managed_file.exists() or managed_file.is_symlink():
            stale_paths.add(managed_file)

    return sorted(stale_paths, key=str)


def build_expected_directories(
    managed_roots: tuple[Path, ...],
    expected_paths: set[Path],
) -> set[Path]:
    """Collect provider directories required by generated output paths."""

    expected_directories: set[Path] = set()
    for expected_path in expected_paths:
        managed_root = next(
            (root for root in managed_roots if expected_path.is_relative_to(root)),
            None,
        )

        if managed_root is None:
            continue

        parent = expected_path.parent
        while parent.is_relative_to(managed_root):
            expected_directories.add(parent)

            if parent == managed_root:
                break
            parent = parent.parent

    return expected_directories


def find_stale_paths(
    path: Path,
    expected_outputs: dict[Path, OutputFile],
    expected_directories: set[Path],
) -> set[Path]:
    """Find maximal stale subtrees without traversing symlink targets."""

    if not path.exists() and not path.is_symlink():
        return set()

    if path in expected_outputs:
        output = expected_outputs[path]

        if output.link_target is None and (path.is_symlink() or path.is_dir()):
            return {path}

        return set()

    if path not in expected_directories or path.is_symlink() or not path.is_dir():
        return {path}

    stale_paths: set[Path] = set()
    for child in path.iterdir():
        stale_paths.update(find_stale_paths(child, expected_outputs, expected_directories))

    return stale_paths


def apply_changes(
    workspace: Workspace,
    diffs: list[DiffEntry],
    stale_paths: list[Path],
) -> None:
    """Replace managed outputs with the generated manifest."""

    for stale_path in stale_paths:
        delete_path(stale_path)

        logger.info("Deleted %s", stale_path)

    for diff in diffs:
        output = diff.output

        if output.link_target is None:
            write_text(output.target_path, output.content)

            logger.info("Wrote %s", output.target_path)

    for diff in diffs:
        output = diff.output

        if output.link_target is not None:
            write_symlink(output.target_path, output.link_target)

            logger.info("Linked %s -> %s", output.target_path, expected_link_text(output))


def report_diffs(diffs: list[DiffEntry], stale_paths: list[Path]) -> None:
    """Log generated differences and stale paths."""

    for diff in diffs:
        logger.info("%s: %s", diff.output.target_path, diff_summary(diff))

    for stale_path in stale_paths:
        logger.info("%s: will be deleted", stale_path)


def diff_summary(diff: DiffEntry) -> str:
    """Produce a concise unified diff for one generated output."""

    if diff.output.link_target is not None:
        return f"symlink -> {expected_link_text(diff.output)}"

    existing = diff.existing or ""
    lines = list(
        difflib.unified_diff(
            existing.splitlines(),
            diff.output.content.splitlines(),
            fromfile="current",
            tofile="expected",
            lineterm="",
        )
    )

    if not lines:
        return "(trailing newline difference)" if existing != diff.output.content else "(no changes)"

    return "\n".join(lines[:MAX_DIFF_LINES])
