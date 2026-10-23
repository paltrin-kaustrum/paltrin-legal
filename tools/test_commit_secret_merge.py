"""Standalone synthetic Git/Gitleaks merge and unreadable-patch checks.

Uses only the standard library, local Git and an explicitly supplied local
scanner. No real credentials, remotes, credential validation or network calls.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().with_name("scan_commit_secrets.py")
SPEC = importlib.util.spec_from_file_location("standalone_commit_guard", SCANNER)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True,
        text=True, encoding="utf-8",
    ).stdout.strip()


def initialize(root: Path) -> str:
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Synthetic local fixture")
    git(root, "config", "user.email", "synthetic@example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    git(root, "config", "gc.auto", "0")
    (root / "ordinary.txt").write_text("ordinary root\n", encoding="utf-8")
    return commit(root, "ordinary root")


def commit(root: Path, message: str) -> str:
    git(root, "add", ".")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


@unittest.skipUnless(
    os.environ.get("PALTRIN_TEST_GITLEAKS"),
    "CLI integration checks require an explicit local scanner path",
)
class CommitSecretMergeTests(unittest.TestCase):
    def test_merge_resolution_only_secret_is_rejected(self):
        tool = os.environ["PALTRIN_TEST_GITLEAKS"]
        with tempfile.TemporaryDirectory(prefix="paltrin-merge-guard-") as temporary:
            root = Path(temporary)
            base = initialize(root)
            git(root, "checkout", "-b", "left")
            (root / "left.txt").write_text("legitimate left content\n", encoding="utf-8")
            left = commit(root, "legitimate left branch")
            git(root, "checkout", "-b", "right", base)
            (root / "right.txt").write_text("legitimate right content\n", encoding="utf-8")
            right = commit(root, "legitimate right branch")
            for parent in (left, right):
                self.assertEqual(
                    guard.scan(root, base, parent, tool, event="pull_request")["findings_count"],
                    0,
                )
            git(root, "checkout", "left")
            git(root, "merge", "--no-commit", "right")
            self.assertTrue((root / ".git" / "MERGE_HEAD").is_file())
            token = "gh" + "p_" + hashlib.sha256(b"synthetic merge-resolution guard fixture").hexdigest()[:36]
            filename = "merge-resolution-only.txt"
            (root / filename).write_text("token=" + token + "\n", encoding="utf-8")
            head = commit(root, "synthetic merge resolution only")
            self.assertEqual(len(git(root, "rev-list", "--parents", "-n", "1", head).split()), 3)
            self.assertEqual(git(root, "remote"), "")
            result = guard.scan(root, base, head, tool, event="pull_request")
            self.assertGreater(result["findings_count"], 0)
            self.assertTrue(any(item["file"] == filename and item["rule"] == "github-pat" for item in result["findings"]))
            self.assertNotIn(token, json.dumps(result))

    def test_unreadable_git_blob_fails_closed_with_safe_cli_result(self):
        tool = os.environ["PALTRIN_TEST_GITLEAKS"]
        with tempfile.TemporaryDirectory(prefix="paltrin-unreadable-guard-") as temporary:
            root = Path(temporary)
            base = initialize(root)
            (root / "unreadable.txt").write_text("ordinary content with a disposable blob\n", encoding="utf-8")
            head = commit(root, "ordinary addition")
            command = [sys.executable, str(SCANNER), "--root", str(root), "--base", base,
                       "--head", head, "--event", "pull_request", "--tool", tool]
            clean = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(clean.returncode, 0)
            self.assertEqual(json.loads(clean.stdout)["findings_count"], 0)

            blob = git(root, "rev-parse", head + ":unreadable.txt")
            objects = (root / ".git" / "objects").resolve()
            target = (objects / blob[:2] / blob[2:]).resolve()
            self.assertTrue(target.is_relative_to(objects))
            self.assertTrue(target.is_file())
            target.chmod(0o600)  # Git marks loose objects read-only on Windows.
            target.unlink()  # Deliberately corrupt only the synthetic repository.
            failed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(json.loads(failed.stdout)["secret_guard"], "failed")
            self.assertNotIn("fatal:", failed.stdout + failed.stderr)
            self.assertNotIn("ordinary content", failed.stdout + failed.stderr)


if __name__ == "__main__":
    unittest.main()
