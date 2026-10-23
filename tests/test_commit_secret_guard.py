"""Synthetic local Git/Gitleaks boundary tests; no real credentials or network."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("commit_secret_guard", ROOT / "tools" / "scan_commit_secrets.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class CommitSecretGuardTests(unittest.TestCase):
    def test_commit_ids_reject_options_and_revisions(self):
        for value in ("--all", "main", "a" * 39, "A" * 40, "a" * 40 + " --all"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                guard.scan(ROOT, value, "b" * 40, "unused")

    @unittest.skipUnless(os.environ.get("PALTRIN_TEST_GITLEAKS"), "CLI integration runs require explicit local scanner path")
    def test_history_range_and_suppressions(self):
        tool = os.environ["PALTRIN_TEST_GITLEAKS"]
        with tempfile.TemporaryDirectory(prefix="paltrin-secret-guard-test-") as temporary:
            root = Path(temporary)

            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args], check=True,
                                      capture_output=True, text=True).stdout.strip()

            def commit(name):
                git("add", ".")
                git("commit", "-m", name)
                return git("rev-parse", "HEAD")

            git("init")
            git("config", "user.name", "Synthetic audit")
            git("config", "user.email", "synthetic@example.invalid")
            # Deliberately synthetic provider-shaped token assembled at runtime.
            token = "gh" + "p_" + hashlib.sha256(b"synthetic secret guard fixture").hexdigest()[:36]
            (root / "historical.txt").write_text("token=" + token, encoding="utf-8")
            first = commit("historical fixture")
            (root / "historical.txt").unlink()
            base = commit("remove historical fixture")
            (root / "ordinary.txt").write_text("ordinary content", encoding="utf-8")
            clean = commit("legitimate addition")
            self.assertEqual(guard.scan(root, base, clean, tool)["findings_count"], 0)
            # Ordinary PRs may lag a newer main commit. Scan their introduced
            # history from the shared ancestor; push mode still rejects divergence.
            git("checkout", "-b", "synthetic-main", base)
            (root / "main-only.txt").write_text("new main commit", encoding="utf-8")
            advanced_main = commit("main advanced after branch creation")
            self.assertEqual(guard.scan(root, advanced_main, clean, tool,
                                       event="pull_request")["findings_count"], 0)
            with self.assertRaises(ValueError):
                guard.scan(root, advanced_main, clean, tool)
            git("checkout", "-B", "synthetic-pr", clean)
            # A newly introduced token must fail even when a PR adds all three
            # suppression mechanisms accepted by normal local Gitleaks usage.
            (root / "new.txt").write_text("token=" + token + " # gitleaks:allow", encoding="utf-8")
            (root / ".gitleaks.toml").write_text('[allowlist]\npaths=[".*"]\n', encoding="utf-8")
            (root / ".gitleaksignore").write_text("*", encoding="utf-8")
            malicious = commit("synthetic new token and attempted suppressions")
            result = guard.scan(root, base, malicious, tool)
            self.assertGreater(result["findings_count"], 0)
            self.assertGreater(guard.scan(root, advanced_main, malicious, tool,
                                          event="pull_request")["findings_count"], 0)
            serialized = json.dumps(result)
            self.assertNotIn(token, serialized)
            self.assertNotIn("Match", serialized)
            self.assertNotIn("Secret", serialized)
            with self.assertRaises(ValueError):
                guard.scan(root, malicious, first, tool)


if __name__ == "__main__":
    unittest.main()
