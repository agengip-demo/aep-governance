"""Check `protected-paths`: fail when a pull request changes agent.protected_paths and its
author is not in repository.platform_team.

Usage (in the CI job):
    yq -o=json . profiles/demo.yaml > profile.json
    git diff --name-only BASE...HEAD | python3 protected_paths.py \
        --profile-json profile.json --author <opener> --author <commit author> ...

Patterns are anchored at the repository root. `**` matches any number of path segments,
`*` and `?` stay within one segment. Standard library only (runs on a bare runner).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterable


def _translate(pattern: str) -> re.Pattern[str]:
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def matches(path: str, patterns: Iterable[str]) -> bool:
    path = path.strip().lstrip("/")
    return any(_translate(p.lstrip("/")).match(path) for p in patterns)


def violations(
    changed: Iterable[str], patterns: list[str], authors: list[str], platform_team: list[str]
) -> list[str]:
    """Protected paths changed in the pull request, unless every author is in the team.

    `authors` holds the pull request opener and the author of every commit in the range;
    an empty list or an unknown (empty) login counts as outside the team.
    """
    if authors and not outsiders(authors, platform_team):
        return []
    return sorted({p.strip() for p in changed if p.strip() and matches(p, patterns)})


def outsiders(authors: list[str], platform_team: list[str]) -> list[str]:
    team = {m.lower() for m in platform_team}
    return sorted({a or "<unknown>" for a in authors if not a or a.lower() not in team})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-json", required=True)
    parser.add_argument("--author", action="append", default=[], required=True)
    args = parser.parse_args(argv)
    with open(args.profile_json, encoding="utf-8") as fh:
        profile = json.load(fh)
    patterns = list(profile["agent"]["protected_paths"])
    team = list(profile["repository"]["platform_team"])
    changed = sys.stdin.read().splitlines()
    found = violations(changed, patterns, args.author, team)
    who = ", ".join(outsiders(args.author, team) or args.author)
    if not found:
        print(f"protected-paths: ok ({len(changed)} changed files checked, authors {who})")
        return 0
    for path in found:
        print(
            f"[protected-paths] {path}: this path is protected ({', '.join(patterns)}) and "
            f"these authors are not in the platform team: {who}. "
            f"Required change: revert the change "
            f"to {path} in this pull request; only the platform team may change it."
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
