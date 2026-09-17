"""Validate the upstream-watch workflow before anyone commits it.

This job rebases and pushes on a schedule with nobody watching, so the checks
that matter are the ones proving it CANNOT push in the situations where pushing
would be wrong. YAML validity is the least of it.

Run it against the real workflow:      python3 upstream-watch-check.py
against any file:                      python3 upstream-watch-check.py PATH
or prove the checks still refuse:      python3 upstream-watch-check.py --selftest

The --selftest matters more than it looks. Until 2026-09-18 this script had
only ever been run against the workflow as written -- a passing input -- and a
checker that has only seen green is indistinguishable from one that prints
"all checks passed" unconditionally. Driven by mutation, 8 of the 9 checks
refused as advertised and the 9th crashed with a traceback instead of naming
its finding. Both facts were discoveries, not reassurances, and neither was
available from reading the code. Same technique as crate-closure.py's
selftest and as trap 42 in agent_docs/verification-and-gating.md: prove a
refusal by making it refuse.
"""
import pathlib
import subprocess
import sys
import tempfile

import yaml

DEFAULT_WF = pathlib.Path(
    "/home/tenfourty/repos/warpgate/.forgejo/workflows/upstream-watch.yml")


def validate(WF: pathlib.Path, verbose: bool = True) -> list[str]:
    """Return the list of reasons this workflow must not be committed.

    An empty list means every check passed. Nothing here writes or executes
    the workflow; `sh -n` parses a run: block without running it.
    """
    def say(msg):
        if verbose:
            print(msg)

    doc = yaml.safe_load(WF.read_text())
    say("YAML parses")

    steps = doc["jobs"]["watch"]["steps"]
    by_name = {s.get("name", s.get("uses", "?")): s for s in steps}
    say(f"steps: {len(steps)}")

    fail: list[str] = []

    # 1. every run: block is valid shell
    for s in steps:
        if "run" not in s:
            continue
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(s["run"])
            tmp = f.name
        r = subprocess.run(["sh", "-n", tmp], capture_output=True, text=True)
        if r.returncode != 0:
            fail.append(f"shell syntax error in step {s.get('name')!r}: {r.stderr.strip()}")
    say("all run: blocks parse as shell" if not fail else "SHELL ERRORS")

    # 2. exactly one step pushes, and it is gated on a clean replay
    pushers = [s for s in steps if "run" in s and "git push" in s["run"]]
    if len(pushers) != 1:
        fail.append(f"expected exactly 1 pushing step, found {len(pushers)}: "
                    f"{[s.get('name') for s in pushers]}")
    else:
        cond = str(pushers[0].get("if", ""))
        if "outcome == 'clean'" not in cond:
            fail.append(f"the pushing step is not gated on a clean replay; its if: is {cond!r}")
        else:
            say(f"only one step pushes, gated on: {cond}")

    # 3. the conflict-reporting step must NOT push
    rep = by_name.get("report a conflict to the ops inbox")
    if rep is None:
        fail.append("no conflict-reporting step")
    elif "git push" in rep["run"]:
        fail.append("the conflict path pushes -- it must not")
    else:
        say("conflict path does not push")

    # 4. a missing token must fail, not skip
    if rep is not None and "exit 1" not in rep["run"]:
        fail.append("a missing OPS_INBOX_TOKEN would not fail the job -- silent conflict")
    else:
        say("missing token fails the job rather than skipping")

    # 5. the replay step must abort the rebase on conflict
    rep2 = by_name.get("replay our patches onto the new release")
    if rep2 is None or "rebase --abort" not in rep2["run"]:
        fail.append("the replay step does not abort a failed rebase")
    else:
        say("failed rebase is aborted")

    # 6. conflicts are captured BEFORE the abort clears them
    #
    # Guarded on BOTH substrings being present. Unguarded, str.index raised
    # ValueError the moment check 5 had already found the abort missing, so a
    # workflow with two defects reported a Python traceback and none of its
    # findings -- the run still failed, so nothing bad got through, but the
    # operator saw a stack trace instead of the reason. Found by mutation on
    # 2026-09-18, not by reading.
    if rep2 is not None:
        r = rep2["run"]
        if "--diff-filter=U" not in r:
            fail.append("the replay step never reads the conflicting paths "
                        "(--diff-filter=U is absent), so no report can name them")
        elif "rebase --abort" not in r:
            pass  # already reported by check 5; nothing coherent to order here
        elif r.index("--diff-filter=U") > r.index("rebase --abort"):
            fail.append("conflicting paths are read AFTER the abort, so the report names nothing")
        else:
            say("conflicting paths captured before the abort")

    # 7. NO ${{ }} expression may survive inside a run: block.
    #
    # Two failure modes at once. A `schedule` event supplies no inputs, so an
    # inputs expression on that path has nothing to render. And any expression
    # spliced into script text is executed as shell, which makes a dispatch input
    # a command-injection vector -- single-quoting does not save it, because a
    # value containing a single quote closes the quote. Expressions belong in
    # `env:` and `if:`, where they are data and conditions respectively.
    leaked = []
    for s in steps:
        if "run" not in s:
            continue
        if "${{" in s["run"]:
            bad = [ln.strip()[:70] for ln in s["run"].splitlines() if "${{" in ln]
            leaked.append((s.get("name"), bad))
    if leaked:
        for name, lines in leaked:
            fail.append(f"step {name!r} interpolates expressions into shell: {lines}")
    else:
        say("no ${{ }} expressions inside any run: block")

    # 8. every input is referenced with a || '' fallback, so the schedule path
    #    cannot depend on how an absent context renders.
    raw = WF.read_text()
    for inp in ("new_tag", "old_tag", "branch_prefix"):
        if f"inputs.{inp} ||" not in raw:
            fail.append(f"inputs.{inp} is used without a `|| ''` fallback")
    if all(f"inputs.{i} ||" in raw for i in ("new_tag", "old_tag", "branch_prefix")):
        say("all three inputs have a || '' fallback for the schedule path")

    # 9. the JSON report body is built by jq, not string concatenation --
    #    conflict paths come from upstream's tree and may contain quotes.
    if rep is not None:
        if "jq -n" not in rep["run"]:
            fail.append("the report body is not built with jq; a path containing a "
                        "quote would produce malformed JSON and lose the report")
        else:
            say("report body built with jq --arg (escapes upstream-supplied paths)")

    return fail


# ---------------------------------------------------------------------------
# Selftest: one mutation per check, each breaking exactly the thing that check
# claims to catch. A check that does not refuse its own mutant is asleep.
# ---------------------------------------------------------------------------
def _sub_once(text: str, old: str, new: str) -> str:
    n = text.count(old)
    if n != 1:
        raise AssertionError(f"anchor appears {n}x, expected 1: {old[:60]!r}")
    return text.replace(old, new)


# (name, mutate, the phrase the resulting failure must contain)
MUTATIONS = [
    ("shell syntax error is caught",
     lambda t: _sub_once(t, '          echo "upstream: $NEW"', '          if [ -z ; then'),
     "shell syntax error"),
    ("a second pushing step is caught",
     lambda t: _sub_once(t, '          echo "upstream: $NEW"',
                         '          git push origin sneaky\n          echo "upstream: $NEW"'),
     "expected exactly 1 pushing step"),
    ("a push on the conflict path is caught",
     lambda t: _sub_once(t, '          echo "reported"',
                         '          git push origin HEAD\n          echo "reported"'),
     "the conflict path pushes"),
    ("a missing token that does not fail the job is caught",
     lambda t: _sub_once(t, '            exit 1\n          fi', '            exit 0\n          fi'),
     "would not fail the job"),
    ("a missing rebase --abort is caught",
     lambda t: _sub_once(t, '            git rebase --abort || true\n', ''),
     "does not abort a failed rebase"),
    ("capturing conflicts after the abort is caught",
     lambda t: _sub_once(
         t,
         '            CONFLICTS=$(git diff --name-only --diff-filter=U | tr \'\\n\' \' \')\n'
         '            echo "conflicts: $CONFLICTS"\n'
         '            git rebase --abort || true\n',
         '            git rebase --abort || true\n'
         '            CONFLICTS=$(git diff --name-only --diff-filter=U | tr \'\\n\' \' \')\n'
         '            echo "conflicts: $CONFLICTS"\n'),
     "AFTER the abort"),
    ("an expression interpolated into a run: block is caught",
     lambda t: _sub_once(t, '          echo "upstream: $NEW"',
                         '          echo "${{ inputs.new_tag }}"\n          echo "upstream: $NEW"'),
     "interpolates expressions into shell"),
    ("an input without its || '' fallback is caught",
     lambda t: _sub_once(t, "IN_NEW:    ${{ inputs.new_tag || '' }}",
                         "IN_NEW:    ${{ inputs.new_tag }}"),
     "without a `|| ''` fallback"),
    ("a report body not built with jq is caught",
     lambda t: _sub_once(t, '          jq -n --arg new "$NEW"',
                         '          printf \'%s\' --arg new "$NEW"'),
     "not built with jq"),
]


def selftest(wf: pathlib.Path) -> int:
    passed = total = 0

    def expect(name, ok):
        nonlocal passed, total
        total += 1
        if ok:
            passed += 1
            print(f"  ok    {name}")
        else:
            print(f"  FAIL  {name}")

    print("upstream-watch-check.py selftest")
    if not wf.exists():
        print(f"  FAIL  cannot read the workflow at {wf}")
        return 2
    text = wf.read_text()

    # The pristine file must PASS, or every mutant below proves nothing: a
    # validator that refuses everything is as useless as one that refuses
    # nothing, and only this line tells the two apart.
    expect("the real workflow passes every check", validate(wf, verbose=False) == [])

    work = pathlib.Path(tempfile.mkdtemp(prefix="upstream-watch-selftest-"))
    for name, mutate, phrase in MUTATIONS:
        try:
            mutated = mutate(text)
        except AssertionError as e:
            # The anchor moved. Reporting this as a pass would be the worst
            # outcome: a mutation that no longer applies tests nothing.
            print(f"  FAIL  {name} -- mutation did not apply: {e}")
            total += 1
            continue
        p = work / (name.replace(" ", "-")[:40] + ".yml")
        p.write_text(mutated)
        try:
            fails = validate(p, verbose=False)
        except Exception as e:                              # noqa: BLE001
            print(f"  FAIL  {name} -- validate() raised {type(e).__name__}: {e}")
            total += 1
            continue
        expect(name, any(phrase in f for f in fails))

    print(f"\n  {passed}/{total} selftest assertions passed")
    return 0 if passed == total else 1


def main() -> int:
    args = sys.argv[1:]
    if "--selftest" in args:
        rest = [a for a in args if a != "--selftest"]
        return selftest(pathlib.Path(rest[0]) if rest else DEFAULT_WF)

    wf = pathlib.Path(args[0]) if args else DEFAULT_WF
    fail = validate(wf)
    print()
    if fail:
        for f_ in fail:
            print(f"  FAIL: {f_}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
