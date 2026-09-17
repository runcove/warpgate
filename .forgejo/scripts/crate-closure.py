#!/usr/bin/env python3
"""Can these crates compile in the bare-Rust test container?

Written 2026-09-17 after run 503 burned nineteen minutes of runner time to
report a COMPILE error -- `Assets::get` not found in warpgate-web -- that was
knowable for free. warpgate-web is #[derive(RustEmbed)] over
../warpgate-web/dist, which exists only after `just openapi && just npm run
build` under Node 24 (docker/Dockerfile.cove). The test container is bare
rust:1-bookworm with no Node, so any crate whose dependency closure reaches
warpgate-web cannot compile there, and cargo aborts the WHOLE invocation on
the first such crate -- taking every other crate's tests down with it.

This answers the question from `cargo metadata`, which resolves the real
dependency graph and compiles nothing: ~0.2 s, offline, no load on this
machine. That matters -- baba runs LibreNMS, the SSH bastion and the DRBD
quorum witness, and the workflow's own test step is named "never on baba".
A real `cargo check` of the five-crate invocation would answer the same
question by doing the thing this box must not do.

LIMITATION, RECORDED NOT HIDDEN: this proves the closure is free of crates
known to need a build step. It does NOT prove the code compiles -- a genuine
type error still needs a compiler. It is a cheap necessary condition, not a
sufficient one, and it is aimed squarely at the failure that actually happened.

Usage:
  crate-closure.py <crate> [<crate>...]   # exit 1 if any cannot build here
  crate-closure.py --selftest

Exit: 0 all clear, 1 at least one crate reaches a blocked crate, 2 could not
resolve the graph, 3 usage.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

# Self-locating: .forgejo/scripts/crate-closure.py -> scripts -> .forgejo ->
# repo root. Lives in this repo, next to the workflow it reads, because it
# reads THAT FILE for the stub marker -- a copy in another repo would answer
# questions about a workflow it cannot see. `.forgejo/` exists only on our
# patch branches (upstream v0.28.6 has neither .forgejo/ nor scripts/), so
# this adds no rebase conflict surface against upstream.
#
# It was developed at ~/.local/state/warpgate-arc/crate-closure.py, which is
# unversioned; that copy is kept only until this one has run from here, then
# deleted so there is one of it.
REPO = pathlib.Path(__file__).resolve().parents[2]

# Crates that embed warpgate-web/dist, which npm builds and a bare rust
# container cannot.
EMBEDS_FRONTEND = {"warpgate-web", "warpgate-web-desktop", "warpgate-web-ssh"}

WORKFLOW = REPO / ".forgejo/workflows/build-image.yml"
# The test container can satisfy those crates IF it creates the directory
# first: rust-embed's derive accepts an EMPTY folder and generates a normal
# Assets::get returning None. That is measured, not assumed -- forge run 506
# (wip/protocol-http-tests, 2026-09-17) compiled warpgate-protocol-http with
# nothing but `mkdir -p warpgate-web/dist` and ran its 72 tests green.
#
# So this is deliberately tied to the workflow TEXT rather than hardcoded
# either way. Delete the mkdir and this check starts refusing the frontend
# crates again, which is exactly what should happen -- the guard tracks the
# evidence instead of outliving it.
STUB_MARKER = "mkdir -p warpgate-web/dist"


def frontend_is_stubbed() -> bool:
    try:
        return STUB_MARKER in WORKFLOW.read_text()
    except OSError:
        # Cannot read the workflow -> assume the stub is NOT there. A guard
        # that fails open is not a guard.
        return False


def needs_frontend() -> set[str]:
    return set() if frontend_is_stubbed() else EMBEDS_FRONTEND


def resolve() -> dict[str, set[str]]:
    """{package name: set of its direct workspace deps}, from cargo metadata.

    --offline first because it is ~0.2 s when the local cache can satisfy the
    lockfile. It cannot always: on 2026-09-17 the cache held rcgen 0.14.8
    while Cargo.lock pinned 0.14.9, and offline resolution failed outright.
    Falling back to an index fetch costs ~28 s and still compiles nothing --
    which is the point, against nineteen minutes of runner time. Never treat
    the offline failure as an answer; it is a cache state, not a verdict.
    """
    for args in (["--offline", "--format-version", "1"],
                 ["--format-version", "1"]):
        out = subprocess.run(["cargo", "metadata", *args],
                             cwd=REPO, capture_output=True, text=True)
        if out.returncode == 0:
            break
    else:
        raise RuntimeError(out.stderr.strip()[:400] or "cargo metadata failed")
    meta = json.loads(out.stdout)
    # id -> name, then walk `resolve.nodes` so this is cargo's own resolution
    # rather than a re-reading of Cargo.toml (which is what I hand-rolled
    # first, and which would miss a dep added under [target.*] or a feature).
    names = {p["id"]: p["name"] for p in meta["packages"]}
    graph: dict[str, set[str]] = {}
    for node in meta["resolve"]["nodes"]:
        graph[names[node["id"]]] = {
            names[d] for d in node["dependencies"] if d in names}
    return graph


def closure(graph: dict[str, set[str]], start: str) -> set[str]:
    seen: set[str] = set()
    queue = [start]
    while queue:
        n = queue.pop()
        if n in seen:
            continue
        seen.add(n)
        queue.extend(graph.get(n, ()))
    return seen


def check(crates: list[str]) -> int:
    try:
        graph = resolve()
    except (RuntimeError, json.JSONDecodeError, KeyError) as e:
        print(f"REFUSING: could not resolve the dependency graph: {e}",
              file=sys.stderr)
        return 2

    blocked = needs_frontend()
    stubbed = frontend_is_stubbed()
    print(f"  frontend stub in the workflow: "
          f"{'PRESENT' if stubbed else 'ABSENT'} "
          f"({STUB_MARKER!r} in {WORKFLOW.name})")

    bad = 0
    for c in crates:
        if c not in graph:
            print(f"FAIL {c}: not a package in this workspace")
            bad += 1
            continue
        hit = sorted(closure(graph, c) & blocked)
        if hit:
            print(f"FAIL {c}: closure reaches {hit} -- needs warpgate-web/dist, "
                  f"which the bare test container cannot build without "
                  f"{STUB_MARKER!r} in the test command. cargo aborts the whole "
                  f"invocation on this, so every other -p crate's tests are "
                  f"lost with it.")
            bad += 1
        else:
            print(f"  ok  {c}: {len(closure(graph, c))} crates in closure")
    print(f"checked {len(crates)} crate(s): {bad} that cannot build in the "
          f"test container")
    return 1 if bad else 0


def selftest() -> int:
    passed = total = 0

    def expect(name, got, want):
        nonlocal passed, total
        total += 1
        if got == want:
            passed += 1
            print(f"  ok    {name}")
        else:
            print(f"  FAIL  {name} (got {got!r}, want {want!r})")

    print("crate-closure.py selftest")
    try:
        graph = resolve()
    except Exception as e:                                  # noqa: BLE001
        print(f"  FAIL  could not resolve the graph: {e}")
        return 2

    php = closure(graph, "warpgate-protocol-http")

    # BOTH directions, driven explicitly rather than by whatever the live
    # workflow happens to say today. Without the stub, the run 503 failure
    # must still be caught; with it, the crate must be allowed -- and a
    # selftest that only exercised today's state would silently stop
    # testing the other half the moment the workflow changed.
    expect("without the stub, warpgate-protocol-http is REJECTED (run 503)",
           bool(php & EMBEDS_FRONTEND), True)
    expect("with the stub, warpgate-protocol-http is ALLOWED (run 506)",
           bool(php & set()), False)

    # The four that never needed the stub must pass either way.
    for c in ("warpgate-common", "warpgate-common-http",
              "warpgate-protocol-ssh", "warpgate-core"):
        expect(f"{c} is accepted regardless of the stub",
               bool(closure(graph, c) & EMBEDS_FRONTEND), False)

    # The workflow-text coupling itself: an unreadable workflow must fail
    # CLOSED, never open.
    real = WORKFLOW.exists() and STUB_MARKER in WORKFLOW.read_text()
    expect("frontend_is_stubbed() agrees with the workflow on disk",
           frontend_is_stubbed(), real)
    expect("needs_frontend() is empty exactly when the stub is present",
           needs_frontend() == set(), real)
    # A crate that does not exist must be caught, not silently skipped.
    expect("an unknown crate name is not silently accepted",
           "warpgate-not-a-crate" in graph, False)
    # And the closure must be non-trivial -- a graph that resolved to nothing
    # would make every crate "clean" (agent_docs/verification-and-gating.md).
    expect("the graph is non-trivial (an empty one would pass everything)",
           len(closure(graph, "warpgate-core")) > 5, True)

    print(f"crate-closure selftest: {passed}/{total}")
    return 0 if passed == total else 2


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 3
    if args[0] == "--selftest":
        return selftest()
    return check(args)


if __name__ == "__main__":
    sys.exit(main())
