"""Run the watcher's shell against a synthetic repository, before it ever runs for real.

upstream-watch-check.py validates the workflow's STRUCTURE: one pushing step,
gated; the conflict path reports and does not push; no expression interpolated
into a run: block. All static. None of it executes a line of the shell, so the
first real execution of the resolve and replay logic would otherwise be the
scheduled fire, unattended, on the repository we actually care about.

This runs those steps' ACTUAL TEXT -- extracted from the workflow file, not
retyped -- against a throwaway git repository built to have the shape the real
one has. Everything it asserts is a behaviour the static checks cannot see:
which branch becomes OLD, whether a version sort or a lexical sort decides it,
what happens when upstream's API hands back the string "null", whether the gate
that decides if anything runs at all can return both of its answers, and
whether a conflicting rebase leaves the tree clean and names the files it
stopped on.

Deliberately NOT covered here, because they need credentials or a remote:
the push step, and the report step's POST. Their guards are what
upstream-watch-check.py asserts statically. This file is about the half that
can be proven on this machine, and the point is that it is a much larger half
than it looks.

The "already current?" step was in neither list when this file was first
written -- not covered, and not declared uncovered either, which is the worse
of the two states: a gap nobody had decided to accept. It needs no credentials
and no remote, and it is the step whose failure is hardest to see from outside
(a watcher wired to "no" is indistinguishable from a quiet upstream). Counting
the steps against the coverage, rather than trusting the list, is what found
it.

Run: python3 .forgejo/scripts/upstream-watch-replay-test.py [PATH-TO-WORKFLOW]
     python3 .forgejo/scripts/upstream-watch-replay-test.py --selftest

--selftest is the answer to "and how do you know THIS file is not asleep?"
(trap 43). It breaks the workflow in ways a reader would call obviously wrong
and requires the assertions above to go red on each, naming the right one. It
lived as a scratch script in /tmp for a day, which meant the proof that this
test refuses anything would have vanished at the next reboot along with the
harness -- so it is here, in git, next to the thing it proves.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

import yaml

DEFAULT_WF = pathlib.Path(__file__).resolve().parents[1] / "workflows/upstream-watch.yml"

passed = total = 0


def expect(name, got, want):
    global passed, total
    total += 1
    if got == want:
        passed += 1
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}\n          got  {got!r}\n          want {want!r}")


def step_run(doc, name):
    """The step's run: block, straight from the workflow -- never a copy."""
    for s in doc["jobs"]["watch"]["steps"]:
        if s.get("name") == name:
            return s["run"]
    raise SystemExit(f"no step named {name!r} in the workflow")


def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def git_ok(repo, *args) -> bool:
    """True iff the command SUCCEEDED.

    Exists because the first draft asserted on git's stdout for questions like
    `merge-base --is-ancestor`, which prints nothing either way -- so the
    assertion compared "" to "" and passed whether the branch existed or not.
    A test that cannot fail is the exact defect this file exists to prevent,
    found in this file while writing it (trap 43).
    """
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=True).returncode == 0


def build_fixture(root: pathlib.Path) -> pathlib.Path:
    """A repo shaped like ours: upstream tags, several cove-patches-v* branches.

    'origin' is a LOCAL clone rather than a network remote, because the shell
    refers to origin/<branch> and we want those refs to exist without reaching
    anything. The workflow's own `git fetch https://github.com/...` line is not
    exercised here; the fetch-failure path it guards is asserted statically.
    """
    up = root / "upstream"
    up.mkdir()
    git(up, "init", "-q", "-b", "main")
    git(up, "config", "user.email", "t@example.invalid")
    git(up, "config", "user.name", "t")
    (up / "README").write_text("base\n")
    git(up, "add", "README")
    git(up, "commit", "-qm", "base")

    # Release tags, including two that a LEXICAL sort would order wrongly:
    # v0.28.10 must beat v0.28.6, and v0.9.0 must not beat either.
    for tag, body in [("v0.9.0", "nine\n"), ("v0.22.0", "twentytwo\n"),
                      ("v0.28.6", "release\n"), ("v0.28.10", "newer\n")]:
        (up / "UPSTREAM").write_text(body)
        git(up, "add", "UPSTREAM")
        git(up, "commit", "-qm", f"upstream {tag}")
        git(up, "tag", tag)

    ours = root / "ours"
    git(root, "clone", "-q", str(up), str(ours))
    git(ours, "config", "user.email", "t@example.invalid")
    git(ours, "config", "user.name", "t")

    # Our patch branches, each based on its own upstream tag, so `rebase --onto
    # NEW OLD` has real work to do.
    # Two independent traps for a lexical sort, not one: "v0.9.0" sorts ABOVE
    # every v0.2x string, and "v0.28.6" sorts above "v0.28.10". A fixture with
    # only the first would pass against a sort that still gets .6 vs .10 wrong.
    for base, branch, patches in [
        ("v0.9.0", "cove-patches-v0.9.0", 1),
        ("v0.22.0", "cove-patches-v0.22.0", 1),
        ("v0.28.6", "cove-patches-v0.28.6", 3),
        ("v0.28.10", "cove-patches-v0.28.10", 2),
    ]:
        git(ours, "checkout", "-q", "-B", branch, base)
        for i in range(patches):
            (ours / f"PATCH{i}").write_text(f"{branch} patch {i}\n")
            git(ours, "add", f"PATCH{i}")
            git(ours, "commit", "-qm", f"{branch} patch {i}")
        git(ours, "push", "-q", "origin", branch)

    # A rehearsal branch, which must NOT be mistaken for a real patch branch.
    git(ours, "checkout", "-q", "-B", "rehearsal/cove-patches-v9.9.9", "v0.28.6")
    git(ours, "push", "-q", "origin", "rehearsal/cove-patches-v9.9.9")

    git(ours, "checkout", "-q", "cove-patches-v0.28.6")
    git(ours, "fetch", "-q", "origin")
    return ours


def run_step(script, repo, env_extra, outputs: pathlib.Path):
    env = dict(os.environ)
    env.update({"GITHUB_OUTPUT": str(outputs)})
    env.update(env_extra)
    r = subprocess.run(["bash", "-c", script], cwd=str(repo),
                       capture_output=True, text=True, env=env)
    got = {}
    if outputs.exists():
        for line in outputs.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                got[k] = v
    return r.returncode, r.stdout + r.stderr, got


def main() -> int:
    wf = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_WF
    if not wf.exists():
        print(f"FAIL: no workflow at {wf}")
        return 2
    doc = yaml.safe_load(wf.read_text())
    resolve = step_run(doc, "resolve what is new and what we are on")
    check = step_run(doc, "already current?")
    replay = step_run(doc, "replay our patches onto the new release")

    root = pathlib.Path(tempfile.mkdtemp(prefix="upstream-watch-replay-"))
    repo = build_fixture(root)
    out = root / "gh-output"

    print("upstream-watch replay test (the workflow's own shell, synthetic repo)")

    # --- resolve --------------------------------------------------------
    out.write_text("")
    rc, log, got = run_step(resolve, repo, {"IN_NEW": "v0.29.0", "IN_OLD": "", "IN_PREFIX": ""}, out)
    expect("resolve succeeds with an explicit new tag", rc, 0)
    expect("NEW is the input, used verbatim", got.get("new"), "v0.29.0")
    # `sort -V` earns its keep twice here: lexically "v0.9.0" would win outright,
    # and among the 0.28 line "v0.28.6" would beat "v0.28.10".
    expect("OLD is the highest patch branch BY VERSION, not lexically",
           got.get("old"), "v0.28.10")
    expect("the rehearsal branch is not mistaken for a patch branch",
           "9.9.9" in str(got.get("old")), False)
    expect("DST carries no prefix when none is given",
           got.get("branch"), "cove-patches-v0.29.0")
    expect("SRC is the branch OLD came from",
           got.get("source_branch"), "cove-patches-v0.28.10")

    out.write_text("")
    rc, log, got = run_step(resolve, repo,
                            {"IN_NEW": "v0.28.10", "IN_OLD": "v0.28.6",
                             "IN_PREFIX": "rehearsal/"}, out)
    expect("an explicit OLD overrides the branch scan", got.get("old"), "v0.28.6")
    expect("branch_prefix lands on the DESTINATION branch only",
           got.get("branch"), "rehearsal/cove-patches-v0.28.10")
    expect("...and not on the source branch",
           got.get("source_branch"), "cove-patches-v0.28.6")

    # The API returning a body without .tag_name makes jq print the STRING
    # "null", which would otherwise be rebased onto as if it were a tag.
    out.write_text("")
    rc, log, got = run_step(resolve, repo, {"IN_NEW": "null", "IN_OLD": "", "IN_PREFIX": ""}, out)
    expect('a tag literally named "null" is refused, not rebased onto', rc, 1)
    expect("...and it says why", "refusing to guess" in log, True)

    # --- already current? ------------------------------------------------
    # The gate that decides whether anything happens at all, and the step with
    # the quietest failure modes in the file. Stuck on "no" the watcher never
    # fires and looks exactly like a calm upstream -- a year could pass before
    # anyone noticed. Stuck on "yes" it replays and pushes every night onto the
    # release it is already on. Neither surfaces as an error anywhere.
    #
    # It is driven from RESOLVE'S OWN OUTPUTS, not from hand-typed values. A
    # hand-typed pair would prove only that `[ "$a" = "$b" ]` compares strings.
    # What needs proving is that the two producers agree on SHAPE: NEW comes
    # from a release tag (`v0.28.10`), OLD from a branch name with
    # `cove-patches-` stripped off it. If either side ever gains or loses the
    # leading "v", the two are never equal, and the only symptom is a job that
    # quietly does a full replay every night forever.
    answers = []
    for label, in_new, want in [
        ("upstream is ahead of us", "v0.29.0", "yes"),
        ("we are already on upstream's newest", "v0.28.10", "no"),
    ]:
        out.write_text("")
        rc, log, got = run_step(resolve, repo,
                                {"IN_NEW": in_new, "IN_OLD": "", "IN_PREFIX": ""}, out)
        expect(f"resolve succeeds when {label}", rc, 0)
        # OLD must name a tag that actually exists upstream. This is the shape
        # check with teeth: if the strip ever yields "0.28.10" or leaves
        # "cove-patches-v0.28.10", it fails HERE, loudly, instead of becoming a
        # comparison that can never come back equal.
        expect(f"...and OLD ({got.get('old')!r}) names a real upstream tag",
               git_ok(repo, "rev-parse", "--verify", "-q",
                      f"refs/tags/{got.get('old')}"), True)
        out.write_text("")
        rc, log, got2 = run_step(check, repo,
                                 {"NEW": got.get("new", ""),
                                  "OLD": got.get("old", "")}, out)
        expect(f"...the gate succeeds when {label}", rc, 0)
        expect(f"...and answers todo={want} when {label}", got2.get("todo"), want)
        answers.append(got2.get("todo"))

    # Trap 44, made an assertion rather than a hope. The two cases above are
    # worth nothing unless the step actually answered them DIFFERENTLY: a gate
    # hard-wired to one constant still passes every individual case that happens
    # to expect that constant. This is the assertion that fails if `todo` cannot
    # vary, and it is the one assertion here that no single-case test can make.
    expect("the gate is capable of both answers, not wired to one",
           sorted(a for a in answers if a), ["no", "yes"])

    # --- replay, clean --------------------------------------------------
    # UPSTREAM_URL points at the local fixture's own origin, so the step's fetch
    # is real but reaches nothing off this machine.
    upstream_url = git(repo, "remote", "get-url", "origin")
    out.write_text("")
    rc, log, got = run_step(
        replay, repo,
        {"NEW": "v0.28.10", "OLD": "v0.28.6", "UPSTREAM_URL": upstream_url,
         "SRC": "cove-patches-v0.28.6", "DST": "rehearsal/cove-patches-v0.28.10"}, out)
    expect("a clean replay reports clean", got.get("outcome"), "clean")
    expect("...and counts the patches it moved", got.get("count"), "3")
    expect("...and the destination branch now exists",
           git_ok(repo, "rev-parse", "--verify", "-q",
                  "refs/heads/rehearsal/cove-patches-v0.28.10"), True)
    expect("...sitting on top of the new tag",
           git_ok(repo, "merge-base", "--is-ancestor", "v0.28.10",
                  "rehearsal/cove-patches-v0.28.10"), True)
    expect("...with every patch present",
           git(repo, "rev-list", "--count",
               "v0.28.10..rehearsal/cove-patches-v0.28.10", check=False), "3")
    # The negative half: the source branch must be untouched by a replay.
    expect("...and the source branch is left where it was",
           git_ok(repo, "merge-base", "--is-ancestor", "v0.28.6",
                  "cove-patches-v0.28.6"), True)

    # --- replay, conflicting --------------------------------------------
    # Make upstream's newest tag touch the same file our patch does, so the
    # rebase cannot apply cleanly. This is the path that must NEVER push.
    git(repo, "checkout", "-q", "cove-patches-v0.28.6")
    conflicted = root / "conflicted"
    shutil.copytree(repo, conflicted)

    # The conflicting tag has to exist UPSTREAM, not just locally: the step
    # fetches it before rebasing, and the first draft of this test created it in
    # the clone, so the fetch failed and the step reported fetch-failed. The
    # dependent assertions below then passed VACUOUSLY -- "no rebase in
    # progress" and "clean working tree" are both trivially true when no rebase
    # was ever attempted. Second vacuous pass found in this file; hence the
    # explicit precondition guard.
    up = root / "upstream"
    git(up, "checkout", "-q", "-B", "clash", "v0.28.10")
    (up / "PATCH0").write_text("upstream wrote this file too\n")
    git(up, "add", "PATCH0")
    git(up, "commit", "-qm", "upstream touches PATCH0")
    git(up, "tag", "v0.29.0")

    out.write_text("")
    rc, log, got = run_step(
        replay, conflicted,
        {"NEW": "v0.29.0", "OLD": "v0.28.6", "UPSTREAM_URL": str(up),
         "SRC": "cove-patches-v0.28.6", "DST": "cove-patches-v0.29.0"}, out)
    expect("a conflicting replay reports conflict", got.get("outcome"), "conflict")
    if got.get("outcome") != "conflict":
        # Do not let the rest pass by default. Everything below is only
        # meaningful if a rebase was actually attempted and actually conflicted.
        expect("PRECONDITION: a rebase was attempted (later checks are void "
               f"without it; step said {got.get('outcome')!r})", False, True)
    else:
        expect("...and names the conflicting path",
               "PATCH0" in str(got.get("conflicts", "")), True)
        expect("...and the step still exits 0, so the report step can run",
               rc, 0)
        # The abort is the thing that stops a half-replayed branch existing.
        expect("...and the rebase is aborted, leaving no rebase in progress",
               (conflicted / ".git/rebase-merge").exists()
               or (conflicted / ".git/rebase-apply").exists(), False)
        expect("...leaving a clean working tree",
               git(conflicted, "status", "--porcelain"), "")
        # And the thing that matters most: no half-replayed branch was pushed,
        # which here means no destination branch was left behind at all.
        expect("...and no destination branch survives the conflict",
               git_ok(conflicted, "merge-base", "--is-ancestor",
                      "v0.29.0", "cove-patches-v0.29.0"), False)

    print(f"\n  {passed}/{total} assertions passed")
    print(f"  fixture: {root}")
    return 0 if passed == total else 1


# Each entry breaks the WORKFLOW -- the subject, never the test -- in a way a
# reader would call obviously wrong, and names the assertion that must catch it.
# The anchor must match exactly once: a mutation whose anchor has moved silently
# becomes a no-op and "passes", which is this file's own subject matter turned
# on itself.
MUTATIONS = [
    # A lexical sort picks v0.9.0 as "highest", replaying the wrong branch onto
    # the new release -- silently, and only once a year.
    ("version-sort-becomes-lexical", "| sort -V | tail -1)", "| sort | tail -1)",
     "OLD is the highest patch branch BY VERSION"),
    # Drop the guard on jq printing the string "null": the job rebases onto a
    # tag named null.
    ("null-tag-guard-removed",
     "''|null) echo \"could not resolve an upstream tag -- refusing to guess\"; exit 1 ;;",
     "''|nullXX) echo \"could not resolve an upstream tag -- refusing to guess\"; exit 1 ;;",
     "refused, not rebased onto"),
    # Capture the conflicting paths AFTER the abort clears them: the report
    # names nothing.
    ("conflicts-read-after-abort",
     '            CONFLICTS=$(git diff --name-only --diff-filter=U | tr \'\\n\' \' \')\n'
     '            echo "conflicts: $CONFLICTS"\n'
     '            git rebase --abort || true\n',
     '            git rebase --abort || true\n'
     '            CONFLICTS=$(git diff --name-only --diff-filter=U | tr \'\\n\' \' \')\n'
     '            echo "conflicts: $CONFLICTS"\n',
     "names the conflicting path"),
    # Do not abort at all: a half-replayed tree is left behind.
    ("no-rebase-abort", "            git rebase --abort || true\n", "",
     "rebase is aborted"),
    # Put the branch prefix on the SOURCE too, so the replay reads from a branch
    # that does not exist.
    ("prefix-leaks-onto-source",
     'echo "source_branch=cove-patches-$OLD"',
     'echo "source_branch=${IN_PREFIX}cove-patches-$OLD"',
     "not on the source branch"),
    # The gate, wired to one answer each way. Stuck on "no" the watcher never
    # fires and looks like a calm upstream; stuck on "yes" it replays nightly
    # onto the release it is already on. Both are invisible in production.
    ("gate-wired-to-no", 'echo "todo=yes" >> "$GITHUB_OUTPUT"',
     'echo "todo=no" >> "$GITHUB_OUTPUT"', "capable of both answers"),
    ("gate-comparison-inverted", 'if [ "$NEW" = "$OLD" ]; then',
     'if [ "$NEW" != "$OLD" ]; then', "answers todo="),
    # Strip the leading "v" off OLD, so NEW ("v0.28.10") and OLD ("0.28.10")
    # can never be equal and the job replays every single night.
    ("old-loses-its-v-prefix", "| sed 's|.*origin/cove-patches-||' \\",
     "| sed 's|.*origin/cove-patches-v||' \\", "names a real upstream tag"),
]


def _run_child(wf_text: str, work: pathlib.Path, name: str):
    p = work / f"{name}.yml"
    p.write_text(wf_text)
    r = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), str(p)],
                       capture_output=True, text=True)
    out = r.stdout + r.stderr
    fails = [ln.strip()[6:].strip() for ln in out.splitlines()
             if ln.strip().startswith("FAIL")]
    return r.returncode, fails


def selftest(wf: pathlib.Path) -> int:
    src = wf.read_text()
    work = pathlib.Path(tempfile.mkdtemp(prefix="upstream-watch-selftest-"))
    print(f"selftest: mutating {wf} and requiring this test to notice\n")

    # A gate that refuses everything is as useless as one that refuses nothing,
    # and only the pristine case tells them apart.
    rc, fails = _run_child(src, work, "pristine")
    if rc != 0:
        print(f"  PRISTINE WORKFLOW FAILS -- nothing below means anything\n    {fails[:3]}")
        return 2
    print("  ok    the unmodified workflow passes")

    missed = []
    for name, old, new, want in MUTATIONS:
        n = src.count(old)
        if n != 1:
            print(f"  FAIL  {name}: anchor matched {n}x, not once -- "
                  "this mutation tests nothing")
            missed.append(name)
            continue
        rc, fails = _run_child(src.replace(old, new), work, name)
        if rc == 0:
            print(f"  FAIL  {name}: the test did NOT notice")
            missed.append(name)
        elif not any(want in f for f in fails):
            print(f"  FAIL  {name}: went red, but not on {want!r}\n"
                  f"          first failure was {fails[0][:90] if fails else '(none)'}")
            missed.append(name)
        else:
            print(f"  ok    {name} -> {want}")

    print()
    if missed:
        print(f"  BLIND SPOTS: {missed}")
        return 1
    print(f"  the test notices every mutation ({len(MUTATIONS)} tried)")
    return 0


if __name__ == "__main__":
    argv = sys.argv[1:]
    if argv and argv[0] == "--selftest":
        rest = argv[1:]
        sys.exit(selftest(pathlib.Path(rest[0]) if rest else DEFAULT_WF))
    sys.exit(main())
