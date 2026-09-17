"""Validate the upstream-watch workflow before anyone commits it.

This job rebases and pushes on a schedule with nobody watching, so the checks
that matter are the ones proving it CANNOT push in the situations where pushing
would be wrong. YAML validity is the least of it.
"""
import pathlib
import subprocess
import sys
import tempfile

import yaml

WF = pathlib.Path("/home/tenfourty/repos/warpgate/.forgejo/workflows/upstream-watch.yml")
doc = yaml.safe_load(WF.read_text())
print("YAML parses")

steps = doc["jobs"]["watch"]["steps"]
by_name = {s.get("name", s.get("uses", "?")): s for s in steps}
print(f"steps: {len(steps)}")

fail = []

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
print("all run: blocks parse as shell" if not fail else "SHELL ERRORS")

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
        print(f"only one step pushes, gated on: {cond}")

# 3. the conflict-reporting step must NOT push
rep = by_name.get("report a conflict to the ops inbox")
if rep is None:
    fail.append("no conflict-reporting step")
elif "git push" in rep["run"]:
    fail.append("the conflict path pushes -- it must not")
else:
    print("conflict path does not push")

# 4. a missing token must fail, not skip
if rep is not None and "exit 1" not in rep["run"]:
    fail.append("a missing OPS_INBOX_TOKEN would not fail the job -- silent conflict")
else:
    print("missing token fails the job rather than skipping")

# 5. the replay step must abort the rebase on conflict
rep2 = by_name.get("replay our patches onto the new release")
if rep2 is None or "rebase --abort" not in rep2["run"]:
    fail.append("the replay step does not abort a failed rebase")
else:
    print("failed rebase is aborted")

# 6. conflicts are captured BEFORE the abort clears them
if rep2 is not None:
    r = rep2["run"]
    if r.index("--diff-filter=U") > r.index("rebase --abort"):
        fail.append("conflicting paths are read AFTER the abort, so the report names nothing")
    else:
        print("conflicting paths captured before the abort")

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
    print("no ${{ }} expressions inside any run: block")

# 8. every input is referenced with a || '' fallback, so the schedule path
#    cannot depend on how an absent context renders.
raw = WF.read_text()
for inp in ("new_tag", "old_tag", "branch_prefix"):
    if f"inputs.{inp} ||" not in raw:
        fail.append(f"inputs.{inp} is used without a `|| ''` fallback")
if all(f"inputs.{i} ||" in raw for i in ("new_tag", "old_tag", "branch_prefix")):
    print("all three inputs have a || '' fallback for the schedule path")

# 9. the JSON report body is built by jq, not string concatenation --
#    conflict paths come from upstream's tree and may contain quotes.
if rep is not None:
    if "jq -n" not in rep["run"]:
        fail.append("the report body is not built with jq; a path containing a "
                    "quote would produce malformed JSON and lose the report")
    else:
        print("report body built with jq --arg (escapes upstream-supplied paths)")

print()
if fail:
    for f_ in fail:
        print(f"  FAIL: {f_}")
    sys.exit(1)
print("all checks passed")
