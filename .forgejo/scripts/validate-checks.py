#!/usr/bin/env python3
"""Refuse a checks.yaml that is malformed or points at an upstream file that
does not exist at the pinned tag.

The second half is the load-bearing part: upstream renaming a workflow would
otherwise leave a check silently pointing at nothing.
"""
import subprocess
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import checks_lib


def main(argv):
    if len(argv) != 2:
        print("usage: validate-checks.py <checks.yaml>", file=sys.stderr)
        return 2
    path = argv[1]
    try:
        checks = checks_lib.load(path)
        tag = checks_lib.upstream_tag(path)
    except ValueError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1

    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", tag, ".github/workflows"],
        capture_output=True, text=True)
    if listing.returncode != 0:
        print(f"INVALID: cannot list {tag}: {listing.stderr.strip()}", file=sys.stderr)
        return 1
    present = {line.split("/")[-1] for line in listing.stdout.split()}
    if not present:
        print(f"INVALID: {tag} has no .github/workflows — an empty listing cannot "
              "tell 'the tag or path is wrong' apart from 'every check was removed', "
              "so refuse rather than blame the checks",
              file=sys.stderr)
        return 1

    bad = [c for c in checks if c["upstream"] not in present]
    for c in bad:
        print(f"INVALID: check {c['name']!r} names upstream workflow "
              f"{c['upstream']!r}, which does not exist at {tag}", file=sys.stderr)
    if bad:
        return 1

    print(f"ok: {len(checks)} check(s) valid against {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
