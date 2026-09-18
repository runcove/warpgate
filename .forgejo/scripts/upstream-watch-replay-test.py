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

COVERAGE IS NOT CLAIMED IN THIS PARAGRAPH. `assert_full_coverage` walks the
workflow at the end of every run, counts the steps carrying a `run:` block
against the ones this file actually executed, and requires the remainder to be
named in UNCOVERED_BY_DESIGN with a reason. It prints the three numbers it
computed. Read those; do not read this header for them.

That machinery exists because the sentence that used to sit here -- "nothing is
excluded any more ... all five of the workflow's logic-bearing steps" -- was
true when written and false by the time it mattered: the fork-CI arc added the
`drift` step between the gate and replay, and nothing re-read the header as a
claim. A prose count is a snapshot of a file that keeps moving; a computed one
cannot drift from its subject.

It mattered beyond tidiness. On 2026-09-18 the first real rehearsal of this
workflow failed on the replay path in CI, between the gate and replay, with an
exit code and no text -- and `drift` was the step that sat there, the one step
no test could have cleared. It WAS the cause, twice over: drift-check.py
imports PyYAML and this workflow never installed it, and the step's `set -uo
pipefail` did not clear the `-e` the runner supplies, so the failing import
killed the step one line before the echo meant to report it. Both fixed
2026-09-19, and both are now assertions here rather than fixes someone
remembers making.

That took three exclusions apart in a row, and each was the same shape: a
sentence that was true of the words and false of the situation.

- "the push step needs credentials or a remote" -- the fixture's origin is a
  local clone, so it already IS a remote and no credential is involved.
- "the report's POST needs a credential and an endpoint" -- it needs *a* token,
  not *the* token, and a loopback listener on an ephemeral port is an endpoint.
- the already-current gate was on no exclusion list at all, which is worse: a
  declared gap is a decision, an undeclared one is an assumption nobody made.
- and now `drift`, which is the same shape a fourth time, arriving by a new
  route: not an exclusion someone wrote, but a step someone added after the
  claim of completeness was made.

The lesson worth keeping is not "test everything". It is that an exclusion
written once is never re-read as a claim, only as a boundary, and the cost of
checking one is usually an afternoon less than it looks.

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
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading

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


# Steps with a run: block that this file deliberately does NOT execute, each
# with the reason. A DECLARED gap is a decision; an undeclared one is an
# assumption nobody made -- and on 2026-09-18 an undeclared one is exactly what
# happened: the header claimed every logic-bearing step was covered, the
# fork-CI arc later added `drift` between the gate and replay, and the claim
# silently became false. `assert_full_coverage` below now makes that
# impossible: a new step is either executed here or named in this dict, and
# nothing else passes.
UNCOVERED_BY_DESIGN = {
    "summary": "echoes three values it is handed and branches on none of them; "
               "there is no behaviour here a test could distinguish from a "
               "working one.",
}
# The `drift` step was here as a TODO carrying homelab-br5.13 -- "needs upstream
# CI files at two tags inside the fixture, which nothing here builds yet". It is
# executed as of 2026-09-19: build_fixture writes .github/workflows at every tag
# and the drift section of main() runs the step's own text four ways. The gap
# that let the inherited--e defect through is closed, and the TODO is gone
# rather than left to read as caution while covering nothing.

_PULLED: set = set()


def step_run(doc, name):
    """The step's run: block, straight from the workflow -- never a copy."""
    for s in doc["jobs"]["watch"]["steps"]:
        if s.get("name") == name:
            _PULLED.add(name)
            return s["run"]
    raise SystemExit(f"no step named {name!r} in the workflow")


def assert_full_coverage(doc, expect):
    """Count the parts against the coverage, rather than trusting a sentence.

    Every step carrying a `run:` block must either have been executed by this
    file or be named in UNCOVERED_BY_DESIGN with a reason. Checked by walking
    the workflow, so it cannot go stale the way prose does.
    """
    logic = [s.get("name") for s in doc["jobs"]["watch"]["steps"] if "run" in s]
    unaccounted = [n for n in logic
                   if n not in _PULLED and n not in UNCOVERED_BY_DESIGN]
    expect(f"every run: step is executed here or declared uncovered "
           f"({len(_PULLED)} executed, {len(UNCOVERED_BY_DESIGN)} declared, "
           f"{len(logic)} in the workflow)",
           unaccounted, [])
    # The other direction: a declared exemption for a step that no longer
    # exists is a stale claim too, and reads as caution while covering nothing.
    stale = [n for n in UNCOVERED_BY_DESIGN if n not in logic]
    expect("no declared exemption names a step that has since been removed",
           stale, [])


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


def inbox_listener():
    """A throwaway HTTP endpoint on loopback, so the report step's POST can run.

    The step needs *a* token, not *the* token: a dummy string proves the header
    is formed and sent, and no credential is involved. Binding to 127.0.0.1 on
    an ephemeral port means nothing leaves this machine, and the real inbox is
    never contacted -- INBOX_URL is a shell default in the workflow for exactly
    this reason, the same shape as UPSTREAM_URL in the replay step.
    """
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            received.append({"path": self.path,
                             "auth": self.headers.get("Authorization", ""),
                             "ctype": self.headers.get("Content-Type", ""),
                             "body": self.rfile.read(n).decode()})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, received


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
    #
    # Each tag also carries upstream's own .github/workflows, because the drift
    # step compares exactly that path between two tags and had nothing to read
    # here until 2026-09-19. The contents are chosen so one adjacent pair has no
    # CI change at all (v0.9.0 -> v0.22.0) and the pair the drift assertions use
    # (v0.28.6 -> v0.28.10) exercises all three verdicts drift-check.py can
    # print about a file: build.yml CHANGED, clippy.yml ADDED, biome.yml
    # REMOVED. build.yml is not an arbitrary pick -- checks.yaml translates it
    # TWICE (release-build and sbom), which is the duplicate-key case
    # drift-check.py has a long comment about and no test.
    WF_AT_TAG = {
        "v0.9.0": {"build.yml": "name: build\n", "biome.yml": "name: biome\n"},
        "v0.22.0": {"build.yml": "name: build\n", "biome.yml": "name: biome\n"},
        "v0.28.6": {"build.yml": "name: build\n", "biome.yml": "name: biome\n"},
        "v0.28.10": {"build.yml": "name: build\non: [push]\n",
                     "clippy.yml": "name: clippy\n"},
    }
    wfdir = up / ".github/workflows"
    for tag, body in [("v0.9.0", "nine\n"), ("v0.22.0", "twentytwo\n"),
                      ("v0.28.6", "release\n"), ("v0.28.10", "newer\n")]:
        (up / "UPSTREAM").write_text(body)
        git(up, "add", "UPSTREAM")
        shutil.rmtree(wfdir, ignore_errors=True)
        wfdir.mkdir(parents=True)
        for fn, text in WF_AT_TAG[tag].items():
            (wfdir / fn).write_text(text)
        # -A so a file DROPPED at this tag is staged as a deletion; scoped by
        # pathspec to the directory this loop owns, inside a throwaway repo.
        git(up, "add", "-A", "--", ".github/workflows")
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

    # The drift step shells out to `.forgejo/scripts/drift-check.py` relative to
    # cwd, and that script resolves checks.yaml relative to ITSELF, so the
    # fixture needs all three at the real layout. Copied, never reimplemented:
    # a reimplementation would test the copy, and the copy is not what runs.
    # This is the first covered step needing anything from the real repo inside
    # the fixture; every other step uses only git.
    here = pathlib.Path(__file__).resolve().parent
    (ours / ".forgejo/scripts").mkdir(parents=True)
    for f in ("drift-check.py", "checks_lib.py"):
        shutil.copy2(here / f, ours / ".forgejo/scripts" / f)
    shutil.copy2(here.parent / "checks.yaml", ours / ".forgejo/checks.yaml")
    # Excluded rather than committed, for one specific reason: the conflict
    # assertions require `git status --porcelain` to come back EMPTY, and three
    # untracked files would make that assertion fail for a reason that has
    # nothing to do with the rebase it is about. Committing them instead would
    # change the patch counts the replay assertions check.
    (ours / ".git/info/exclude").write_text("/.forgejo/\n")

    git(ours, "checkout", "-q", "cove-patches-v0.28.6")
    git(ours, "fetch", "-q", "origin")
    return ours


def fake_apt(root: pathlib.Path, rc: int) -> pathlib.Path:
    """A bin directory whose `apt-get` does nothing and exits `rc`.

    The drift step apt-get installs python3-yaml. Left unstubbed this test gives
    a different answer on every host it runs on: 127 on a machine with no apt at
    all, a real network install inside a Debian job image, a permission failure
    as a non-root user. None of those is the thing under test, and one of them
    reaches the network. Stubbed, whether PyYAML ends up importable is decided
    by this file and nothing else.
    """
    d = root / f"fake-apt-{rc}"
    d.mkdir(exist_ok=True)
    p = d / "apt-get"
    p.write_text(f'#!/bin/sh\nexit {rc}\n')
    p.chmod(0o755)
    return d


def yaml_blocker(root: pathlib.Path) -> pathlib.Path:
    """A PYTHONPATH entry that makes `import yaml` raise, as the job image does.

    Shadows the real PyYAML with a module that raises ModuleNotFoundError -- the
    same exception node:22-bookworm's Python produces, from the same import
    line, and the first half of run 520's silent failure on 2026-09-18.

    The caution that comes with this: the FIRST attempt to simulate that case
    (18 Sep, in a scratch script) ran `python3 -c "import yaml"` on a host where
    yaml was importable, so nothing failed, and the green result was read as the
    hypothesis holding. Every use of this blocker is therefore paired with a
    precondition that the import really does fail under it, and a control that
    it succeeds without it.
    """
    d = root / "no-yaml"
    d.mkdir(exist_ok=True)
    (d / "yaml.py").write_text(
        'raise ModuleNotFoundError("No module named \'yaml\'")\n')
    return d


def can_import_yaml(repo: pathlib.Path, env_extra: dict) -> bool:
    """Does `python3 -c "import yaml"` succeed under exactly this environment?"""
    return subprocess.run(["bash", "-c", 'python3 -c "import yaml"'],
                          cwd=str(repo), capture_output=True, text=True,
                          env={**os.environ, **env_extra}).returncode == 0


def github_env_value(path: pathlib.Path, key: str):
    """One value out of a GITHUB_ENV file, including the `KEY<<DELIM` form.

    Returns None when the key is absent, which is deliberately distinguishable
    from a key present and empty: "the step wrote nothing" and "the step wrote
    an empty report" are the two cases this whole bead is about not confusing.
    """
    lines = path.read_text().splitlines() if path.exists() else []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith(f"{key}<<"):
            delim = ln.split("<<", 1)[1]
            body, i = [], i + 1
            while i < len(lines) and lines[i] != delim:
                body.append(lines[i])
                i += 1
            return "\n".join(body)
        if ln.startswith(f"{key}="):
            return ln.split("=", 1)[1]
        i += 1
    return None


def run_step(script, repo, env_extra, outputs: pathlib.Path,
             env_file: pathlib.Path = None):
    env = dict(os.environ)
    env.update({"GITHUB_OUTPUT": str(outputs)})
    if env_file is not None:
        # Truncated here rather than by the caller so a step that writes nothing
        # leaves an EMPTY file, not the previous step's report to be misread as
        # this one's. GITHUB_ENV must also be set for any step that appends to
        # it: those steps run under `set -u`, where an unset one is a fatal
        # unbound variable and not the behaviour CI would show.
        env_file.write_text("")
        env["GITHUB_ENV"] = str(env_file)
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
    push = step_run(doc, "push the replayed branch")

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

    # --- report how upstream's CI changed ---------------------------------
    # The last step in this workflow that had never executed anywhere, and the
    # one that sits exactly where run 520 died on 2026-09-18 -- between the gate
    # and replay, producing an exit code and no text. Everything below is a
    # property that only running it can establish.
    drift = step_run(doc, "report how upstream's CI changed")
    denv = root / "gh-env"
    blocker = yaml_blocker(root)
    apt_ok, apt_bad = fake_apt(root, 0), fake_apt(root, 100)
    path = os.environ.get("PATH", "")
    with_yaml = {"PATH": f"{apt_ok}:{path}"}
    no_yaml = {"PATH": f"{apt_bad}:{path}", "PYTHONPATH": str(blocker)}

    # The fixture's CI has to differ between the two tags or every assertion
    # below is about the "no change" path wearing a different label.
    expect("PRECONDITION: upstream's CI really does differ across the tags "
           "under test",
           sorted(git(repo, "diff", "--name-only", "v0.28.6", "v0.28.10", "--",
                      ".github/workflows", check=False).split()),
           [".github/workflows/biome.yml",
            ".github/workflows/build.yml",
            ".github/workflows/clippy.yml"])

    # Nothing changed: the only case where a blank-looking report is honest.
    out.write_text("")
    rc, log, _ = run_step(drift, repo,
                          {"OLD": "v0.9.0", "NEW": "v0.22.0", **with_yaml},
                          out, env_file=denv)
    expect("an unchanged upstream CI succeeds", rc, 0)
    expect("...and says which exit code it read", "drift-check.py exited 0" in log, True)
    body = github_env_value(denv, "DRIFT")
    expect("...and reports 'no change' into GITHUB_ENV",
           str(body).startswith("no change:"), True)

    # A real change. Three verdicts in one comparison, and the duplicate-key
    # cross-reference that has only ever been argued for in a comment.
    out.write_text("")
    rc, log, _ = run_step(drift, repo,
                          {"OLD": "v0.28.6", "NEW": "v0.28.10", **with_yaml},
                          out, env_file=denv)
    changed_body = github_env_value(denv, "DRIFT") or ""
    expect("a changed upstream CI still succeeds -- drift is information, "
           "never a build failure", rc, 0)
    expect("...and drift-check.py returns its own code for it, not a failure",
           "drift-check.py exited 3" in log, True)
    expect("...naming the file that changed",
           "build.yml: changed" in changed_body, True)
    expect("...the file upstream ADDED", "clippy.yml: ADDED" in changed_body, True)
    expect("...and the file upstream REMOVED",
           "biome.yml: REMOVED" in changed_body, True)
    # A real result must not be dressed as a refusal, which is the same
    # confusion as the reverse and just as invisible in a one-line summary.
    expect("...and a real verdict is NOT stamped as a failure to complete",
           "DID NOT COMPLETE" in changed_body, False)
    # checks.yaml maps build.yml to TWO of our checks. A 1:1 {upstream: name}
    # dict -- the shape drift-check.py warns against and the obvious way to
    # write it -- keeps only the last and silently under-reports the blast
    # radius. Both names, or this proves nothing.
    #
    # Limit worth knowing: --selftest mutates the workflow and never the scripts
    # it calls, so this pair is outside that harness. It was proven by hand
    # instead, on a throwaway copy of .forgejo (2026-09-19): flattening the dict
    # to `{c["upstream"]: [c["name"]]}` takes the run to 79/80 with exactly
    # "cross-referencing to release-build" red.
    #
    # That result is the argument for asserting BOTH names rather than one. The
    # flattened map does not lose the cross-reference -- it keeps the LAST entry
    # written for the key, so `sbom` still appears and a test that checked only
    # `sbom`, or only "some check was named", would have stayed green through
    # it. Half the answer is the shape of failure this file exists to catch.
    for name in ("release-build (mirrors build.yml)", "sbom (mirrors build.yml)"):
        expect(f"...cross-referencing to {name.split()[0]}",
               name in changed_body, True)

    # THE case. PyYAML unavailable is not hypothetical: it is what the job image
    # actually looks like, and on 2026-09-18 it killed this step one line before
    # the echo meant to report it, leaving exit 1 and no text at all.
    expect("PRECONDITION: PyYAML really is unimportable under the blocked "
           "environment (the first simulation of this case, 18 Sep, ran the "
           "probe where yaml WAS importable and proved nothing)",
           can_import_yaml(repo, no_yaml), False)
    expect("CONTROL: ...and importable without the blocker, so the line above "
           "is the blocker's doing and not a missing python3",
           can_import_yaml(repo, with_yaml), True)

    out.write_text("")
    rc, log, _ = run_step(drift, repo,
                          {"OLD": "v0.28.6", "NEW": "v0.28.10", **no_yaml},
                          out, env_file=denv)
    incomplete_body = github_env_value(denv, "DRIFT") or ""
    expect("a step that cannot run the check still EXITS CLEAN -- a CI change "
           "must never fail this job", rc, 0)
    expect("...and says PyYAML could not be made importable",
           "could not make PyYAML importable" in log, True)
    expect("...and reports the exit code instead of dying at it",
           "drift-check.py exited 1" in log, True)
    expect("...stamping GITHUB_ENV so the refusal survives into the report",
           incomplete_body.startswith("DRIFT-CHECK DID NOT COMPLETE"), True)
    # The distinction this whole step exists to preserve. An absence that reads
    # as 'no change' is the one outcome nobody would ever investigate.
    expect("...and a refusal never reads as a clean 'no change'",
           "no change:" in incomplete_body, False)
    expect("...carrying the real reason, not just a code",
           "ModuleNotFoundError" in incomplete_body, True)

    # apt SUCCEEDING while the module is still unimportable -- the exact hazard
    # the step's comment describes (apt installing for a different python3 than
    # the one on PATH). Verified by importing, not by apt's exit code; this is
    # that sentence turned into a test.
    out.write_text("")
    rc, log, _ = run_step(
        drift, repo,
        {"OLD": "v0.28.6", "NEW": "v0.28.10",
         "PATH": f"{apt_ok}:{path}", "PYTHONPATH": str(blocker)},
        out, env_file=denv)
    expect("a green apt-get is not taken as proof PyYAML is importable",
           "could not make PyYAML importable (apt=0 import=1)" in log, True)

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

    # --- push the replayed branch ----------------------------------------
    # Declared uncovered as "needs credentials or a remote" until the premise
    # was checked: the fixture's origin is a local clone, so it IS a remote and
    # no credential is involved. The step is two lines, and one property of it
    # is worth more than the rest of this file put together -- see below.
    up = root / "upstream"          # the fixture's 'origin', a plain local repo
    DST = "rehearsal/cove-patches-v0.28.10"
    out.write_text("")
    rc, log, _ = run_step(push, repo, {"DST": DST}, out)
    expect("the push step succeeds after a clean replay", rc, 0)
    expect("...and the branch is on the remote", git_ok(up, "rev-parse", "--verify", "-q", DST), True)
    expect("...at exactly the commit we replayed",
           git(up, "rev-parse", DST), git(repo, "rev-parse", DST))
    # The negative: pushing the destination must not drag the source with it.
    expect("...and the source branch was not pushed anywhere new",
           git_ok(up, "rev-parse", "--verify", "-q", "rehearsal/cove-patches-v0.28.6"), False)

    # THE safety property of this whole workflow. It runs on a schedule with
    # nobody watching, and it pushes. If that push can ever overwrite history on
    # the forge, an unattended job destroys work on a branch someone else moved,
    # and the first anyone knows is the missing commits. A non-fast-forward must
    # be REFUSED, not resolved.
    #
    # Diverge the remote's copy, then push again. `up` is checked out on main so
    # the refusal can only be the non-fast-forward, never receive.denyCurrentBranch
    # -- otherwise this would pass for a reason that has nothing to do with safety.
    expect("PRECONDITION: the remote is not sitting on the branch under test",
           git(up, "rev-parse", "--abbrev-ref", "HEAD") != DST, True)
    git(up, "checkout", "-q", "-B", "diverge", DST)
    (up / "REMOTE_MOVED").write_text("someone else pushed here\n")
    git(up, "add", "REMOTE_MOVED")
    git(up, "commit", "-qm", "a commit only the remote has")
    git(up, "branch", "-f", DST, "diverge")
    git(up, "checkout", "-q", "main")
    remote_tip = git(up, "rev-parse", DST)

    out.write_text("")
    rc, log, _ = run_step(push, repo, {"DST": DST}, out)
    expect("a push that would overwrite the remote is REFUSED", rc != 0, True)
    expect("...for the right reason, not some other failure",
           ("non-fast-forward" in log) or ("rejected" in log), True)
    expect("...and the remote still has the commit we did not make",
           git(up, "rev-parse", DST), remote_tip)

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

    # --- report a conflict to the ops inbox -------------------------------
    # The last step that had never executed. Two of its three parts need no
    # credential at all, and the third needs *a* token rather than *the* token.
    report = step_run(doc, "report a conflict to the ops inbox")

    # The token guard decides whether a conflict is ever seen by a human. If it
    # ever skips instead of failing, a conflicted release is discovered when
    # somebody eventually wonders why no new branch appeared -- the workflow's
    # own comment says "could be months". INBOX_URL points at a closed port so
    # that even a removed guard cannot put traffic anywhere real.
    out.write_text("")
    rc, log, _ = run_step(report, repo,
                          {"TOKEN": "", "NEW": "v0.29.0", "COUNT": "3",
                           "CONFLICTS": "PATCH0",
                           "INBOX_URL": "http://127.0.0.1:1/never"}, out)
    expect("a missing token fails the job", rc, 1)
    expect("...naming the secret to fix", "OPS_INBOX_TOKEN is not set" in log, True)
    # Matched as a WHOLE LINE, not a substring. The first draft asked whether
    # "reported" appeared anywhere in the log and it always did -- the guard's
    # own message is "this conflict cannot be reported". A detector that greps
    # for a word finds it inside sentences about that word (trap 41), and this
    # one would have called every run a silent success.
    expect("...and does not quietly report success",
           "reported" in [ln.strip() for ln in log.splitlines()], False)

    # The POST itself, and the claim that has only ever existed in a comment:
    # CONFLICTS holds paths from UPSTREAM's tree, so a filename containing a
    # quote or a backslash must not be able to produce malformed JSON and lose
    # the report at the exact moment it matters.
    srv, received = inbox_listener()
    nasty = 'src/a"b.rs src/back\\slash.rs'
    out.write_text("")
    rc, log, _ = run_step(
        report, repo,
        {"TOKEN": "dummy-not-a-real-token", "NEW": "v0.29.0", "COUNT": "3",
         "CONFLICTS": nasty,
         "INBOX_URL": f"http://127.0.0.1:{srv.server_port}/v1/events/warpgate-upstream"}, out)
    expect("the report step posts and exits clean", rc, 0)
    expect("...with exactly one request reaching the inbox", len(received), 1)
    if len(received) != 1:
        expect("PRECONDITION: a request arrived (everything below is void "
               f"without one; step said rc={rc})", False, True)
    else:
        req = received[0]
        expect("...carrying the bearer token it was handed",
               req["auth"], "Bearer dummy-not-a-real-token")
        expect("...declared as JSON", "application/json" in req["ctype"], True)
        body = None
        try:
            body = json.loads(req["body"])
        except ValueError as exc:
            expect(f"...and the body survives a hostile filename as valid JSON ({exc})",
                   False, True)
        if body is not None:
            expect("...routed to the right source", body.get("source"), "warpgate-upstream")
            expect("...naming the release a human has to act on",
                   body.get("title"), "Warpgate v0.29.0 needs a hand")
            # Intact, not merely parseable: an escaping bug that dropped or
            # mangled the paths would still yield valid JSON and a useless
            # report naming nothing.
            expect("...with the quote-and-backslash paths intact in the message",
                   nasty in body.get("message", ""), True)

    # The JOIN between the two steps, fed with what the drift step ACTUALLY
    # wrote rather than a hand-typed lookalike. The drift step stamps a refusal
    # and this step greps for that stamp, anchored at line start: two halves
    # written at different times that have to agree on one exact string, with
    # nothing to notice if they stop agreeing. A human reading the inbox gets
    # only this sentence -- if it says "did not change" when the check never
    # ran, the failure is invisible at the one place it is read.
    for label, drift_body, want, must_not in [
        ("a drift check that could not complete",
         incomplete_body, "did not complete", "did not change"),
        ("a real upstream CI change", changed_body,
         "3 workflow file(s)", "did not change"),
    ]:
        out.write_text("")
        rc, log, _ = run_step(
            report, repo,
            {"TOKEN": "dummy-not-a-real-token", "NEW": "v0.29.0", "COUNT": "3",
             "CONFLICTS": "PATCH0", "DRIFT": drift_body,
             "INBOX_URL": f"http://127.0.0.1:{srv.server_port}/v1/events/warpgate-upstream"},
            out)
        expect(f"the report step summarises {label}", rc, 0)
        msg = ""
        if received:
            try:
                msg = json.loads(received[-1]["body"]).get("message", "")
            except ValueError:
                pass
        expect(f"...saying {want!r}", want in msg, True)
        expect(f"...and never {must_not!r}", must_not in msg, False)
    # Bounded on purpose: upstream's filenames are not ours to put in another
    # session's inbox. Counts reach the human; the list stays in the run log.
    expect("...and the summary carries counts, not upstream's filenames",
           "build.yml" in msg, False)
    srv.shutdown()

    # Last, so it sees every step_run() this run made.
    assert_full_coverage(doc, expect)

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
    # The one that matters most. A scheduled job that force-pushes can destroy
    # a branch someone else moved, unattended, with the missing commits as the
    # first symptom. Adding six characters must go red here.
    ("push-becomes-force", 'git push origin "$DST"', 'git push --force origin "$DST"',
     "remote still has the commit we did not make"),
    # Swallowing the push failure: the job goes green having pushed nothing,
    # which is how a watcher becomes decorative without anyone noticing.
    ("push-failure-swallowed", 'git push origin "$DST"', 'git push origin "$DST" || true',
     "overwrite the remote is REFUSED"),
    # A missing token that exits 0 means a conflicted release is never reported
    # and the job still goes green -- the failure the step's own comment says
    # could go unnoticed for months.
    ("missing-token-passes-quietly",
     '            echo "Fix the secret; do not let this job pass quietly."\n'
     '            exit 1\n',
     '            echo "Fix the secret; do not let this job pass quietly."\n'
     '            exit 0\n',
     "a missing token fails the job"),
    # Build the report body by string interpolation instead of jq --arg. The
    # workflow's comment says this would lose the report when a conflicting
    # filename contains a quote; this is that comment turned into a test.
    #
    # ANCHOR MAINTENANCE (2026-09-18): this anchor previously described the
    # three-arg report body and stopped matching when the drift detector added
    # `--arg drift "$DRIFT_SUMMARY"` and turned `message` into a jq expression.
    # A stale anchor does not fail loudly on its own -- the mutation simply
    # applies nothing, the test passes, and the pass certifies the opposite of
    # the truth. It was caught only because --selftest counts its own anchor
    # hits and refuses an anchor that matched 0 times. If you change the report
    # body in upstream-watch.yml, this anchor changes with it, in the same
    # commit; the selftest is what will tell you if you forget.
    # THE regression, and the one that actually happened: put back the -e the
    # step inherits from `bash -e`. The step then dies at the first non-zero
    # command with no output at all -- run 520 on 2026-09-18 exactly, which cost
    # three dispatches to narrow down because nothing could distinguish it from
    # a step that had not run.
    ("drift-set-e-restored",
     "          set +e\n"
     "          set -uo pipefail\n"
     "\n"
     "          # drift-check.py imports checks_lib",
     "          set -e\n"
     "          set -uo pipefail\n"
     "\n"
     "          # drift-check.py imports checks_lib",
     "must never fail this job"),
    # Stop stamping the refusal: the report goes into GITHUB_ENV unmarked, and
    # a check that never ran becomes indistinguishable from one that ran and
    # found nothing -- at the one place a human reads it.
    ("drift-failure-reads-as-clean",
     '            { echo "DRIFT-CHECK DID NOT COMPLETE (exit $DRIFT_RC):"; cat "$DRIFT_FILE"; } > "$DRIFT_FILE.tmp"\n'
     '            mv "$DRIFT_FILE.tmp" "$DRIFT_FILE"\n',
     "",
     "stamping GITHUB_ENV"),
    # The same confusion in reverse: treat drift-check.py's 3 (a real verdict:
    # upstream's CI changed) as a failure to complete. The drift IS the answer,
    # and this would file it under "could not tell".
    ("drift-real-result-read-as-refusal",
     'if [ "$DRIFT_RC" -ne 0 ] && [ "$DRIFT_RC" -ne 3 ]; then',
     'if [ "$DRIFT_RC" -ne 0 ]; then',
     "NOT stamped as a failure to complete"),
    # Trust apt's exit code instead of importing. The step's own comment says
    # apt can succeed while installing the module for a different python3; this
    # is that sentence as an executable claim.
    ("drift-yaml-trusted-from-apt-exit-code",
     '          python3 -c "import yaml" 2>/dev/null\n'
     '          YAML_RC=$?\n',
     "          YAML_RC=0\n",
     "not taken as proof PyYAML is importable"),
    ("report-body-interpolated-not-escaped",
     '          jq -n --arg new "$NEW" --arg count "$COUNT" --arg conflicts "$CONFLICTS" \\\n'
     '                --arg drift "$DRIFT_SUMMARY" \\\n'
     '            \'{source: "warpgate-upstream", severity: "warning",\n'
     '              title: "Warpgate \\($new) needs a hand",\n'
     '              message: ("replaying \\($count) patches onto \\($new) stopped at: \\($conflicts)"\n'
     '                        + (if $drift == "" then "" else "\\n\\n" + $drift end))}\' \\\n',
     '          printf \'{"source":"warpgate-upstream","severity":"warning",'
     '"title":"Warpgate %s needs a hand",'
     '"message":"replaying %s patches onto %s stopped at: %s%s"}\' '
     '"$NEW" "$COUNT" "$NEW" "$CONFLICTS" "$DRIFT_SUMMARY" \\\n',
     "hostile filename"),
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
