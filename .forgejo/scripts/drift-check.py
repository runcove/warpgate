#!/usr/bin/env python3
"""Report how upstream's CI changed between two tags.

Runs at the moment the watcher moves us from one release to the next, which is
the only moment it matters: we adopt releases, never upstream's main branch.

Exit codes: 0 nothing changed, 3 upstream's CI changed (a real result, not a
refusal -- deliberately outside the 89-99 "could not run safely" band; see
EXIT_CODES.md), 2 the two tags could not be compared at all (bad usage, a tag
git cannot read, or neither tag has any CI to compare).
"""
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import checks_lib

WF = ".github/workflows"
DEFAULT_CHECKS = pathlib.Path(__file__).resolve().parent.parent / "checks.yaml"


def listing(tag):
    r = subprocess.run(["git", "ls-tree", "-r", "--name-only", tag, WF],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(f"ERROR: cannot read {tag}: {r.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return set(r.stdout.split())


def cross_reference(files, checks_path):
    """Lines naming which of our translated checks are affected, or [].

    A problem here -- a missing checks.yaml, one that fails validation, an
    entry shaped in a way this code does not expect -- is a convenience
    failing, never the drift verdict changing: `main()` has already decided
    0 vs 3 from `files` alone before this is called. Catch everything, not
    just the exception types anticipated today. A `KeyError` from an
    unexpected entry shape must be exactly as harmless here as a missing
    file would be; narrowing this to specific exception types is exactly how
    the next new way for checks.yaml to be malformed turns a correctly
    detected drift into a reported crash (exit 1) instead of exit 3 with an
    honest "could not cross-reference" note.
    """
    try:
        checks = checks_lib.load(str(checks_path))
        # A dict of LISTS, not a 1:1 dict: checks.yaml has real cases of two
        # checks translating the same upstream file (release-build and sbom
        # both mirror build.yml). A 1:1 {upstream: name} mapping silently
        # drops all but the last one written for that key -- confirmed live
        # against build.yml, which is exactly this case -- so a change would
        # be reported as affecting only one of the two checks that need it.
        mirrored = {}
        for c in checks:
            mirrored.setdefault(c["upstream"], []).append(c["name"])
        hits = [f"{name} (mirrors {f.split('/')[-1]})"
                for f in files
                for name in mirrored.get(f.split("/")[-1], [])]
    except Exception as exc:                                  # noqa: BLE001
        return [f"(could not cross-reference {checks_path}: {exc})"]
    if not hits:
        return []
    return ["", "checks we translate that are affected:"] + [f"  * {h}" for h in hits]


def main(argv):
    args = argv[1:]
    checks_path = DEFAULT_CHECKS
    if "--checks" in args:
        i = args.index("--checks")
        if i + 1 >= len(args):
            print("usage: drift-check.py <old-tag> <new-tag> [--checks <path>]",
                  file=sys.stderr)
            return 2
        checks_path = pathlib.Path(args[i + 1])
        del args[i:i + 2]

    if len(args) != 2:
        print("usage: drift-check.py <old-tag> <new-tag> [--checks <path>]",
              file=sys.stderr)
        return 2
    old, new = args

    old_files, new_files = listing(old), listing(new)
    if not old_files and not new_files:
        print(f"ERROR: neither {old} nor {new} has {WF} — refusing to report "
              "'no change' from two empty listings", file=sys.stderr)
        return 2

    changed = subprocess.run(
        ["git", "diff", "--name-only", old, new, "--", WF],
        capture_output=True, text=True)
    if changed.returncode != 0:
        print(f"ERROR: diff failed: {changed.stderr.strip()}", file=sys.stderr)
        return 2
    files = sorted(f for f in changed.stdout.split() if f)

    if not files:
        print(f"no change: upstream's CI is identical between {old} and {new}")
        return 0

    added = sorted(new_files - old_files)
    removed = sorted(old_files - new_files)

    print(f"upstream CI changed between {old} and {new}:")
    for f in files:
        base = f.split("/")[-1]
        if f in added:
            note = "ADDED upstream — consider adopting it"
        elif f in removed:
            note = "REMOVED upstream — consider dropping ours"
        else:
            note = "changed"
        print(f"  - {base}: {note}")

    for line in cross_reference(files, checks_path):
        print(line)

    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
