#!/usr/bin/env python3
"""Refuse a checks.yaml that is malformed or points at an upstream file that
does not exist at the pinned tag.

The second half is the load-bearing part: upstream renaming a workflow would
otherwise leave a check silently pointing at nothing.
"""
import os
import subprocess
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import checks_lib


def _dangling_commands(checks):
    """Refuse a check whose command starts with a repo-relative path that is
    not there, or not executable.

    THE CASE THIS EXISTS FOR. `reprotest` named `.forgejo/scripts/reprotest.sh`
    for as long as the check list has existed, and no such file was ever
    committed. This validator said "ok: 11 check(s) valid" throughout, because
    it checked the SHAPE of an entry and whether its `upstream:` workflow
    existed, and never asked whether the command could run. The check is
    `state: excepted`, so nothing ran it and nothing complained. Un-except it
    and it fails with "No such file or directory" — an ORDINARY-range failure
    no exit code distinguishes from a verdict on our code.

    A validator that cannot tell a real command from a dangling one has the
    same defect as a check that cannot tell a pass from not having looked.

    DELIBERATELY NARROW, and the narrowness is the design rather than a
    shortcut. Only the FIRST token, and only when it looks like a path inside
    the repository. Resolving `cargo deny check` or
    `cd warpgate-web && biome ci .` would mean knowing what is installed
    wherever the check eventually runs — a different machine, inside a sandbox
    image — so it would produce confident false refusals about tools that are
    present there and absent here. That job already belongs to the tools gate
    in run-check.sh, which asks in the right place: at run time, where the
    check actually runs.

    So this catches exactly one class: we named a file of ours, and it is not
    there. Commands that begin with a program name (`cargo`, `helm`, `mkdir`)
    are skipped, and skipped silently, because saying "unchecked" on eight of
    eleven lines every run would train a reader to ignore the output.
    """
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                          capture_output=True, text=True)
    if root.returncode != 0:
        print("INVALID: not inside a git checkout, so repo-relative commands "
              "cannot be resolved — refusing rather than skipping the check",
              file=sys.stderr)
        return True
    root = pathlib.Path(root.stdout.strip())

    bad = False
    for c in checks:
        first = c["command"].split()[0] if c["command"].split() else ""
        # A path inside the repo: has a separator, and is not absolute, not a
        # home-relative path, and not an escape upwards.
        if "/" not in first or first.startswith(("/", "~", "../")):
            continue
        target = root / first
        if not target.is_file():
            print(f"INVALID: check {c['name']!r} runs {first!r}, which does not "
                  f"exist at {target}. A command that is not there fails in the "
                  f"ordinary range and reads like a verdict on the code.",
                  file=sys.stderr)
            bad = True
        elif not os.access(target, os.X_OK):
            print(f"INVALID: check {c['name']!r} runs {first!r}, which exists at "
                  f"{target} but is not executable.", file=sys.stderr)
            bad = True
    return bad


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

    if _dangling_commands(checks):
        return 1

    print(f"ok: {len(checks)} check(s) valid against {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
