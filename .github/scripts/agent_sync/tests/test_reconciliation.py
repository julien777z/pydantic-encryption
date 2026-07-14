import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_sync.configuration import load_agent_model_overrides, load_settings
from agent_sync.generation import generate_outputs
from agent_sync.models.outputs import DiffEntry
from agent_sync.models.runtime import ExitCode
from agent_sync.models.workspace import Workspace
from agent_sync.reconciliation import apply_changes, compute_diffs, compute_stale_paths
from agent_sync.runtime import main


class AuthoritativeOutputTests(unittest.TestCase):
    """Verify generated outputs fully replace every managed agent surface."""

    def test_dirty_tree_matches_generation_from_blank_tree(self) -> None:
        """Make existing provider state irrelevant to final generated output."""

        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            blank_root = temp_root / "blank"
            dirty_root = temp_root / "dirty"
            outside_root = temp_root / "outside"
            outside_root.mkdir()
            sentinel = outside_root / "sentinel.txt"
            sentinel.write_text("keep\n", encoding="utf-8")

            self.create_sources(blank_root)
            self.create_sources(dirty_root)
            self.create_dirty_outputs(dirty_root, outside_root)

            self.synchronize(blank_root)
            self.synchronize(dirty_root)

            self.assertEqual(self.snapshot_managed_tree(blank_root), self.snapshot_managed_tree(dirty_root))
            self.assertTrue(sentinel.exists())
            self.assertFalse((dirty_root / "AGENTS.override.md").exists())
            self.assertNotIn(
                "mcp_servers",
                (dirty_root / ".codex" / "config.toml").read_text(encoding="utf-8"),
            )
            self.assertTrue((dirty_root / ".claude" / "hooks" / "simplify.sh").stat().st_mode & 0o111)

    def test_missing_codex_settings_removes_config_but_keeps_rule_instructions(self) -> None:
        """Delete Codex settings output when its canonical settings file is absent."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_sources(root, include_codex_settings=False)
            config_path = root / ".codex" / "config.toml"
            config_path.parent.mkdir(parents=True)
            config_path.write_text("model = \"manual\"\n", encoding="utf-8")

            self.synchronize(root)

            self.assertFalse(config_path.exists())
            self.assertTrue((root / "AGENTS.md").exists())

    def test_removed_sources_remove_every_previous_output(self) -> None:
        """Prune provider artifacts after their canonical inputs disappear."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_sources(root)
            self.synchronize(root)

            shutil.rmtree(root / ".agents" / "skills" / "example")
            shutil.rmtree(root / ".agents" / "rules")
            (root / ".agents" / "hooks" / "simplify.sh").unlink()
            (root / ".agents" / "agents" / "reviewer.md").unlink()
            (root / ".agents" / "commands" / "check.md").unlink()

            self.synchronize(root)

            self.assertFalse((root / ".claude" / "skills" / "example").exists())
            self.assertFalse((root / ".cursor" / "skills" / "example").exists())
            self.assertFalse((root / ".codex" / "skills" / "example").exists())
            self.assertFalse((root / ".claude" / "hooks" / "simplify.sh").exists())
            self.assertFalse((root / ".cursor" / "agents" / "reviewer.md").exists())
            self.assertFalse((root / ".claude" / "commands" / "check.md").exists())
            self.assertFalse((root / "AGENTS.md").exists())

    def test_second_run_is_idempotent(self) -> None:
        """Report no changes after authoritative output replacement completes."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.create_sources(root)
            (root / ".codex").mkdir()
            (root / ".codex" / "stale.txt").write_text("stale\n", encoding="utf-8")

            initial_diffs, initial_stale = self.pending_changes(root)
            self.assertTrue(initial_diffs)
            self.assertTrue(initial_stale)

            self.synchronize(root)
            final_diffs, final_stale = self.pending_changes(root)

            self.assertEqual(final_diffs, [])
            self.assertEqual(final_stale, [])

    def test_dry_run_reports_without_mutating_managed_tree(self) -> None:
        """Leave stale and divergent outputs untouched during dry-run reporting."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside_root = root / "outside"
            outside_root.mkdir()
            self.create_sources(root)
            self.create_dirty_outputs(root, outside_root)
            initial_snapshot = self.snapshot_managed_tree(root)

            with patch("agent_sync.runtime.WORKSPACE", Workspace(root=root)):
                exit_code = main(["sync", "--dry-run"])

            self.assertEqual(exit_code, ExitCode.DIFFERENCES)
            self.assertEqual(self.snapshot_managed_tree(root), initial_snapshot)

    def create_sources(self, root: Path, *, include_codex_settings: bool = True) -> None:
        """Create a representative canonical agent tree."""

        skill_dir = root / ".agents" / "skills" / "example"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: example\ndescription: Example skill.\n---\n\n# Example\n",
            encoding="utf-8",
        )

        rules_dir = root / ".agents" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "python.md").write_text(
            "---\nalwaysApply: true\n---\n\n# Python\n\nUse modern Python.\n",
            encoding="utf-8",
        )

        hooks_dir = root / ".agents" / "hooks"
        hooks_dir.mkdir(parents=True)
        (hooks_dir / "simplify.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")

        agents_dir = root / ".agents" / "agents"
        agents_dir.mkdir(parents=True)
        (agents_dir / "reviewer.md").write_text(
            "---\nname: reviewer\ndescription: Review changes.\n---\n\nReview the changes.\n",
            encoding="utf-8",
        )

        commands_dir = root / ".agents" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "check.md").write_text("# Check\n\nRun checks.\n", encoding="utf-8")

        settings_dir = root / ".agents" / "settings"
        settings_dir.mkdir(parents=True)
        (settings_dir / "claude.json").write_text(
            json.dumps({"model": "claude-test"}),
            encoding="utf-8",
        )

        if include_codex_settings:
            (settings_dir / "codex.json").write_text(
                json.dumps(
                    {
                        "approval_policy": "never",
                        "sandbox_mode": "danger-full-access",
                        "project_doc_max_bytes": 1,
                    }
                ),
                encoding="utf-8",
            )

    def create_dirty_outputs(self, root: Path, outside_root: Path) -> None:
        """Populate managed surfaces with conflicting and orphaned state."""

        config_path = root / ".codex" / "config.toml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(
            "model = \"manual\"\n\n[mcp_servers.manual]\nurl = \"https://example.invalid\"\n",
            encoding="utf-8",
        )

        config_path.chmod(0o755)

        (root / ".codex" / "orphan.txt").write_text("orphan\n", encoding="utf-8")

        stale_dir = root / ".claude" / "orphan" / "nested"
        stale_dir.mkdir(parents=True)
        (stale_dir / "file.txt").write_text("orphan\n", encoding="utf-8")

        hook_path = root / ".claude" / "hooks" / "simplify.sh"
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("wrong\n", encoding="utf-8")
        hook_path.chmod(0o644)

        (root / ".claude" / "external").symlink_to(outside_root)
        (root / ".cursor").symlink_to(outside_root)

        (root / "AGENTS.override.md").write_text("manual\n", encoding="utf-8")

    def pending_changes(self, root: Path) -> tuple[list[DiffEntry], list[Path]]:
        """Return exact generated differences and stale managed paths."""

        workspace = Workspace(root=root)
        settings = load_settings(workspace)
        outputs = generate_outputs(workspace, settings, load_agent_model_overrides(workspace))

        return compute_diffs(workspace, outputs), compute_stale_paths(workspace, outputs)

    def synchronize(self, root: Path) -> None:
        """Apply one authoritative synchronization pass."""

        workspace = Workspace(root=root)
        settings = load_settings(workspace)
        outputs = generate_outputs(workspace, settings, load_agent_model_overrides(workspace))
        apply_changes(
            workspace,
            compute_diffs(workspace, outputs),
            compute_stale_paths(workspace, outputs),
        )

    def snapshot_managed_tree(self, root: Path) -> dict[str, tuple]:
        """Capture managed paths without following symlinks."""

        snapshot: dict[str, tuple] = {}
        for relative_path in (Path(".claude"), Path(".cursor"), Path(".codex")):
            self.capture_path(root, root / relative_path, snapshot)

        for filename in ("AGENTS.md", "AGENTS.override.md"):
            self.capture_path(root, root / filename, snapshot)

        return snapshot

    def capture_path(self, root: Path, path: Path, snapshot: dict[str, tuple]) -> None:
        """Capture one path recursively while preserving its concrete type."""

        if not path.exists() and not path.is_symlink():
            return

        relative_path = str(path.relative_to(root))
        if path.is_symlink():
            snapshot[relative_path] = ("link", os.readlink(path))

            return

        if path.is_file():
            snapshot[relative_path] = (
                "file",
                path.read_bytes(),
                bool(path.stat().st_mode & 0o111),
            )

            return

        snapshot[relative_path] = ("directory",)
        for child in sorted(path.iterdir()):
            self.capture_path(root, child, snapshot)


if __name__ == "__main__":
    unittest.main()
