"""Scan newly introduced Git commits with a pinned, local Gitleaks CLI.

The caller supplies trusted event commit IDs. Repository ignore/config files and
inline suppression comments cannot weaken this guard. No credential validation
or raw secret-bearing scanner output is emitted or retained.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

VERSION = "8.30.1"
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def scan(root: Path, base: str, head: str, tool: str, *, event: str = "push") -> dict:
    if not COMMIT.fullmatch(base) or not COMMIT.fullmatch(head):
        raise ValueError("Expected full lowercase base and head commit IDs")
    for commit in (base, head):
        subprocess.run(["git", "-C", str(root), "cat-file", "-e", commit + "^{commit}"],
                       check=True, capture_output=True)
    if event not in {"push", "pull_request"}:
        raise ValueError("Unsupported scan event")
    if event == "pull_request":
        shared = subprocess.run(["git", "-C", str(root), "merge-base", base, head],
                                check=True, capture_output=True, text=True).stdout.strip()
        if not COMMIT.fullmatch(shared):
            raise ValueError("Pull request requires a shared commit ancestor")
        base = shared
    ancestor = subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", base, head],
                              capture_output=True)
    if ancestor.returncode != 0:
        raise ValueError("Base must be an ancestor of head; resolve history before scanning")
    version = subprocess.run([tool, "version"], check=True, capture_output=True, text=True).stdout.strip()
    if version != VERSION:
        raise ValueError("Unexpected Gitleaks CLI version")
    commit_range = base + ".." + head
    # Gitleaks can report success after Git fails to read a patch. Independently
    # prove the same merge-inclusive range is readable; discard every patch byte.
    subprocess.run([
        "git", "-C", str(root), "log", "--patch", "--diff-merges=first-parent",
        "--no-ext-diff", "--no-textconv", "--no-color", commit_range,
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    with tempfile.TemporaryDirectory(prefix="paltrin-secret-guard-") as temporary:
        stage = Path(temporary)
        config = stage / "gitleaks.toml"
        config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        ignores = stage / "empty.ignore"
        ignores.write_text("", encoding="utf-8")
        report = stage / "redacted.json"
        result = subprocess.run([
            tool, "git", str(root), "--config", str(config),
            "--gitleaks-ignore-path", str(ignores), "--ignore-gitleaks-allow",
            "--log-opts=--diff-merges=first-parent " + commit_range, "--redact=100", "--no-banner",
            "--no-color", "--report-format", "json", "--report-path", str(report),
        ], cwd=stage, capture_output=True, text=True)
        if result.returncode not in (0, 1):
            raise RuntimeError("Gitleaks execution failed; raw output withheld")
        if not report.is_file():
            raise RuntimeError("Gitleaks did not produce its required redacted report")
        findings = json.loads(report.read_text(encoding="utf-8"))
        # Intentionally omit Match, Secret, author, email and source-line fields.
        metadata = [{"rule": item["RuleID"], "file": item["File"],
                     "line": item["StartLine"], "commit": item["Commit"]} for item in findings]
        if result.returncode == 1 and not metadata:
            raise RuntimeError("Gitleaks failed without a readable result")
        return {"gitleaks_version": VERSION, "base": base, "head": head,
                "findings_count": len(metadata), "findings": metadata,
                "scope": "introduced commits only; existing history is assessed separately"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tool", default="gitleaks")
    parser.add_argument("--event", choices=("push", "pull_request"), default="push")
    args = parser.parse_args()
    try:
        report = scan(args.root, args.base, args.head, args.tool, event=args.event)
    except Exception as error:
        print(json.dumps({"secret_guard": "failed", "reason": type(error).__name__,
                          "detail": "Unable to prove a clean scan; raw output withheld"}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 1 if report["findings_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
