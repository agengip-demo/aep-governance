"""Reject project files that would weaken the central `security` scanners (gitleaks, Trivy,
npm audit via .npmrc registry or audit settings).

gitleaks and Trivy read configuration and ignore lists from the scanned directory
and honour inline suppressions. The pipeline passes its own configuration, and this
check fails when a project tries to bring its own.

Usage: python3 scanner_overrides.py <repository dir>    (exit 1 on findings)
Standard library only.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

FORBIDDEN_FILES = {
    ".gitleaks.toml",
    "gitleaks.toml",
    ".gitleaksignore",
    "trivy.yaml",
    "trivy.yml",
    ".trivy.yaml",
    ".trivyignore",
    ".trivyignore.yaml",
    ".npmrc",
}
INLINE_MARKERS = ("gitleaks:allow", "trivy:ignore", "tfsec:ignore")
SKIP_DIRS = {".git", "node_modules", ".aep-governance"}
MAX_BYTES = 2_000_000


def _finding(where: str, problem: str, fix: str) -> str:
    return f"[security-config] {where}: {problem} Required change: {fix}"


def find_overrides(root: Path) -> list[str]:
    root = Path(root)
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if name in FORBIDDEN_FILES:
                out.append(
                    _finding(
                        rel,
                        "scanner configuration or ignore lists are set centrally.",
                        f"delete {rel}; ask the platform team if a finding is a false positive.",
                    )
                )
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                text = path.read_bytes().decode("utf-8", errors="ignore")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                marker = next((m for m in INLINE_MARKERS if m in line), None)
                if marker:
                    out.append(
                        _finding(
                            f"{rel}:{lineno}",
                            f"inline scanner suppression `{marker}` is not allowed.",
                            "remove the suppression and fix the finding.",
                        )
                    )
    return out


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path(".")
    findings = find_overrides(root)
    for f in findings:
        print(f)
    if findings:
        return 1
    print("security-config: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
