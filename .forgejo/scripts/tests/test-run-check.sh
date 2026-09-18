#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${RUN_CHECK:-$HERE/../run-check.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

# Cases below exercise run-check.sh's own CI-leak guard (RUN_CHECK_DRY,
# RUN_CHECK_FORCE_STATE, RUN_CHECK_FORCE_RC under CI/GITHUB_ACTIONS/
# FORGEJO_ACTIONS). Clear any ambient CI markers first so the cases above
# and below that one stay deterministic regardless of how this suite itself
# is invoked -- mirrors test-hardened-run.sh.
unset CI GITHUB_ACTIONS FORGEJO_ACTIONS

# A reporting check that FAILS must not fail the job.
out=$(RUN_CHECK_FORCE_RC=1 "$SCRIPT" cargo-deny 2>&1); rc=$?
[ $rc -eq 0 ] && ok "a failing reporting check does not fail the job" \
  || bad "reporting check failed the job (rc=$rc)"
grep -qi "report" <<<"$out" && ok "says it is report-only" || bad "silent about being report-only: $out"

# A blocking check that FAILS must fail the job. Without this, promoting a check
# to blocking would change nothing at all.
out=$(RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=1 "$SCRIPT" cargo-deny 2>&1); rc=$?
[ $rc -ne 0 ] && ok "a failing blocking check fails the job" \
  || bad "blocking check passed while failing -- promotion would be meaningless"

# A blocking check that PASSES must pass.
RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=0 "$SCRIPT" cargo-deny >/dev/null 2>&1
[ $? -eq 0 ] && ok "a passing blocking check passes" || bad "false alarm on a good check"

# An excepted check is skipped, and says why and until when.
out=$("$SCRIPT" reprotest 2>&1); rc=$?
[ $rc -eq 0 ] && ok "excepted check does not fail the job" || bad "excepted check failed (rc=$rc)"
grep -qi "review_by\|2026-12-18" <<<"$out" && ok "names the review date" \
  || bad "skipped silently -- indistinguishable from a deleted check: $out"

# A compiling check must go through the hardened wrapper; a non-compiling one must not.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>&1)
grep -q "hardened-run" <<<"$out" && ok "compiling check is capped" \
  || bad "clippy ran uncapped -- see global constraints: $out"
out=$(RUN_CHECK_DRY=1 "$SCRIPT" cargo-deny 2>&1)
grep -q "hardened-run" <<<"$out" && bad "non-compiling check needlessly capped" \
  || ok "non-compiling check runs directly"

# 'unverified' must be treated as compiling -- the safe direction.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" schema-compat 2>&1)
grep -q "hardened-run" <<<"$out" && ok "'unverified' is treated as compiling" \
  || bad "'unverified' ran uncapped -- unsafe default: $out"

# An unknown check name must fail loudly, not silently pass.
"$SCRIPT" no-such-check >/dev/null 2>&1
[ $? -ne 0 ] && ok "unknown check name is refused" || bad "unknown check passed"

# FIX ROUND 1 ADDENDUM: a missing check-name argument is a refusal (93), not
# an ordinary exit 1 -- same defect, same fix, as hardened-run.sh's
# HARDENED_RUN_IMAGE case and cache-env.sh's missing-bucket/S3_ENDPOINT cases.
out=$("$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "missing check-name argument exits 93, not a bare 1" \
  || bad "missing check-name argument did not exit 93 (rc=$rc): $out"

# FIX ROUND 1, Major 1: exit codes 89-99 are hardened-run.sh's reserved
# "could not run safely" band. A refusal there is not a statement about the
# check, so it must NEVER be downgraded by state: reporting -- nine of the
# ten real checks are reporting, including all four compiling ones, i.e.
# every check that can ever reach hardened-run.sh at all. Tested against
# clippy (compiling, reporting) with both documented codes (90-93) and one
# deliberately undocumented mid-band code (95), plus the band's own edges
# (89, 99), to prove the whole range is covered, not just the codes named
# in a comment somewhere.
for code in 89 90 91 92 93 95 97 99; do
  out=$(RUN_CHECK_FORCE_RC=$code "$SCRIPT" clippy 2>&1); rc=$?
  [ $rc -ne 0 ] && ok "exit $code on a reporting check still fails the job" \
    || bad "exit $code was swallowed by reporting state -- read as a lint result"
  grep -qi "report-only" <<<"$out" \
    && bad "exit $code was reported as an ordinary report-only result: $out" \
    || ok "exit $code is not reported as an ordinary check result"
done

# The band has edges: a code just outside 89-99 on either side must still go
# through the ordinary reporting/blocking logic, not be swallowed as a
# refusal by an over-wide range check.
for code in 88 100; do
  out=$(RUN_CHECK_FORCE_RC=$code "$SCRIPT" clippy 2>&1); rc=$?
  [ $rc -eq 0 ] && ok "exit $code (outside the band) still follows reporting state" \
    || bad "exit $code (outside the band) was treated as a refusal (rc=$rc): $out"
  grep -qi "report-only" <<<"$out" && ok "exit $code is reported as an ordinary result" \
    || bad "exit $code (outside the band) lost its ordinary report-only reporting: $out"
done

# The reviewer's own reproduction: a refusal must fail even a *blocking*
# check that was told, via the test hooks, to report PASS. `[ $rc -ne 0 ]`
# alone cannot tell this apart from an ORDINARY blocking failure -- a
# blocking check that fails also exits non-zero, so disabling the whole
# refusal-band check would still leave this "ok" (a real regression the
# review caught by mutation). Must also assert the REFUSE-specific message,
# which only the refusal branch prints.
out=$(RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=90 "$SCRIPT" clippy 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "^REFUSE clippy" <<<"$out" \
  && ok "a refusal fails a blocking check too, reported as REFUSE not an ordinary blocking FAIL" \
  || bad "a refusal on a blocking check either passed (rc=$rc) or wasn't reported as REFUSE (indistinguishable from an ordinary blocking FAIL): $out"

# FIX ROUND 1, Major 2: run-check.sh's own test hooks need the same CI-leak
# guard hardened-run.sh already has (same three markers, same exit code) --
# otherwise a leaked RUN_CHECK_FORCE_RC/RUN_CHECK_FORCE_STATE/RUN_CHECK_DRY
# silently defeats every check this script runs.
out=$(FORGEJO_ACTIONS=true RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=0 \
      "$SCRIPT" clippy 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses leaked RUN_CHECK_FORCE_STATE/RUN_CHECK_FORCE_RC under CI" \
  || bad "did not refuse under CI (rc=$rc) -- the reviewer's PASS-without-running reproduction: $out"

out=$(CI=true RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses leaked RUN_CHECK_DRY under CI" \
  || bad "did not refuse leaked RUN_CHECK_DRY under CI (rc=$rc): $out"
grep -q "RUN_CHECK_DRY" <<<"$out" && ok "names RUN_CHECK_DRY as the offender" \
  || bad "did not name the offending variable: $out"

out=$(GITHUB_ACTIONS=true RUN_CHECK_FORCE_RC=0 "$SCRIPT" clippy 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses leaked RUN_CHECK_FORCE_RC alone under CI" \
  || bad "did not refuse leaked RUN_CHECK_FORCE_RC under CI (rc=$rc): $out"
grep -q "RUN_CHECK_FORCE_RC" <<<"$out" && ok "names RUN_CHECK_FORCE_RC as the offender" \
  || bad "did not name the offending variable: $out"

# MINOR: a lookup that hangs must not hang run-check.sh forever -- a timeout
# is a refusal, not a pass. $SCRIPT (not a hardcoded path -- this must honour
# RUN_CHECK the same as every other case here, or a mutation to the timeout
# logic itself would go untested) is symlinked next to a stub lookup-check.py
# that never returns, so the timeout WRAPPER is what's under test, not
# lookup-check.py's own correctness.
TIMEOUT_DIR="${TMPDIR:-/tmp}/run-check-timeout-test.$$"
mkdir -p "$TIMEOUT_DIR"
ln -sf "$SCRIPT" "$TIMEOUT_DIR/run-check.sh"
ln -sf "$HERE/fixtures/lookup-check-hang.py" "$TIMEOUT_DIR/lookup-check.py"
start=$(date +%s)
out=$(RUN_CHECK_LOOKUP_TIMEOUT=1 "$TIMEOUT_DIR/run-check.sh" clippy 2>&1); rc=$?
elapsed=$(( $(date +%s) - start ))
rm -rf "$TIMEOUT_DIR"
[ "$rc" -ne 0 ] && ok "a hung lookup fails the job, not a silent pass" \
  || bad "a hung lookup exited 0"
[ "$elapsed" -lt 10 ] && ok "the hang is bounded (took ${elapsed}s, not left to run 30s)" \
  || bad "run-check.sh waited out the full hang (${elapsed}s) -- no timeout took effect"
grep -qi "timed out\|timeout" <<<"$out" && ok "names it as a timeout, not a generic failure" \
  || bad "timeout was not named: $out"

# FIX ROUND 1 (Task 5's fix round): a capped check must forward the seven
# cache/credential variable NAMES to hardened-run.sh via --forward-env; an
# uncapped check must never invoke hardened-run.sh at all. Proven against a
# stub hardened-run.sh's own recorded argv -- what run-check.sh actually
# calls it with -- using the same symlink substitution the timeout case
# above uses for lookup-check.py, not a claim about run-check.sh's source.
#
# Uses a synthetic checks.yaml (fixtures/checks-forward-test.yaml), not the
# real one: the real checks' commands (`cargo deny check`, `just clippy`, ...)
# are real, network-touching tools on this host -- an earlier version of
# this test called the real `cargo-deny` for its "uncapped" case and it
# spent minutes fetching an advisory-db over git before being killed. This
# test only needs to know which path run-check.sh takes, not whether a real
# check tool passes, and "true" as both fixture commands makes the uncapped
# path's real `bash -lc "true"` instant and harmless either way.
FORWARD_DIR="${TMPDIR:-/tmp}/run-check-forward-test.$$"
mkdir -p "$FORWARD_DIR"
ln -sf "$SCRIPT" "$FORWARD_DIR/run-check.sh"
ln -sf "$HERE/../lookup-check.py" "$FORWARD_DIR/lookup-check.py"
ln -sf "$HERE/fixtures/hardened-run-stub.sh" "$FORWARD_DIR/hardened-run.sh"
FAKE_CHECKS="$HERE/fixtures/checks-forward-test.yaml"

ARGS_FILE="$FORWARD_DIR/hardened-run-args"
CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  "$FORWARD_DIR/run-check.sh" fake-capped >/dev/null 2>&1
for v in RUSTC_WRAPPER SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_S3_USE_SSL \
         SCCACHE_S3_NO_CREDENTIALS AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY; do
  grep -qx -- "--forward-env" "$ARGS_FILE" 2>/dev/null && grep -qx "$v" "$ARGS_FILE" 2>/dev/null \
    && ok "forwards $v to hardened-run.sh on the capped path" \
    || bad "did not forward $v to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"
done

# TASK 7B: the capped container starts empty -- hardened-run.sh puts nothing
# in it on its own -- so every capped check must be given --source/--workdir,
# or its command runs against nothing and fails looking exactly like a real
# bug in the code under test.
grep -qx -- "--source" "$ARGS_FILE" 2>/dev/null \
  && ok "passes --source to hardened-run.sh on the capped path" \
  || bad "did not pass --source to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"
grep -qx -- "--workdir" "$ARGS_FILE" 2>/dev/null && grep -qx "/src" "$ARGS_FILE" 2>/dev/null \
  && ok "passes --workdir /src to hardened-run.sh on the capped path" \
  || bad "did not pass --workdir /src to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"

# FIX ROUND 1: hardened-run.sh names no project, so it does not know
# "Cargo.toml" is the right file to look for -- that knowledge is
# run-check.sh's own (this IS a cargo workspace), passed through explicitly.
grep -qx -- "--verify-file" "$ARGS_FILE" 2>/dev/null && grep -qx "Cargo.toml" "$ARGS_FILE" 2>/dev/null \
  && ok "passes --verify-file Cargo.toml to hardened-run.sh on the capped path" \
  || bad "did not pass --verify-file Cargo.toml to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"

rm -f "$ARGS_FILE"
out=$(CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  "$FORWARD_DIR/run-check.sh" fake-uncapped 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "the uncapped fixture check still passes" || bad "fake-uncapped failed (rc=$rc): $out"
[ ! -e "$ARGS_FILE" ] && ok "an uncapped check never invokes hardened-run.sh at all" \
  || bad "fake-uncapped still called hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"
rm -rf "$FORWARD_DIR"

# ---------------------------------------------------------------------------
# Task 7A: a check whose declared `tools:` are missing refuses (97) before
# running anything, instead of running and reporting whatever the missing
# tool's own failure happens to look like (measured 2026-09-18:
# `check-lockfile.sh` reported PASS with jq missing).
# ---------------------------------------------------------------------------
TOOLS_FIXTURE="$HERE/fixtures/checks-tools-test.yaml"

# A self-contained PATH: only what run-check.sh itself needs to execute at
# all (bash for its own shebang, dirname/timeout/cut/python3 for its own
# body) -- never a PATH="" or similarly total restriction, which would break
# bash's own execution and produce a 127 from the wrong thing, proving
# nothing. "cargo" is deliberately absent from it -- not uninstalled
# anywhere on this machine, just left out of this self-contained PATH -- so
# the ONLY thing missing, from run-check.sh's point of view, is the
# declared tool under test.
TOOLS_BIN="${TMPDIR:-/tmp}/run-check-tools-test.$$"
mkdir -p "$TOOLS_BIN"
for b in bash dirname timeout cut python3; do
  ln -sf "$(command -v "$b")" "$TOOLS_BIN/$b"
done

# Step 4(a): declared tool absent exits 97 BEFORE running anything -- proven
# by the check's own distinctive output never appearing, not merely by the
# exit code (a check that ran and happened to also exit 97 would pass a
# bare `rc -eq 97` just as well).
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$TOOLS_BIN" "$SCRIPT" fake-missing-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "declared tool absent: exits 97" \
  || bad "declared tool absent: expected rc=97, got rc=$rc: $out"
grep -q "cargo" <<<"$out" && ok "declared tool absent: names the missing tool" \
  || bad "declared tool absent: message does not name cargo: $out"
grep -q "SHOULD_NOT_RUN_MARKER" <<<"$out" \
  && bad "declared tool absent: the check's command ran anyway: $out" \
  || ok "declared tool absent: the command never ran"

# Every missing tool is reported, not just the first -- reporting only one
# per run is how a four-tool gap takes four CI runs to discover, and each
# of those runs costs a human a read.
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$TOOLS_BIN" "$SCRIPT" fake-missing-multi 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "multiple declared tools absent: exits 97" \
  || bad "multiple declared tools absent: expected rc=97, got rc=$rc: $out"
grep -q "cargo" <<<"$out" && grep -q "made-up-tool-zzz" <<<"$out" \
  && ok "multiple declared tools absent: names all of them, not just the first" \
  || bad "multiple declared tools absent: did not name both missing tools: $out"

# Step 4(c): a state: reporting check that refuses with 97 is NOT printed as
# an ordinary report-only FAIL -- reuse the same declared-missing-tool case
# (state: reporting) and assert both the non-zero exit AND the absence of
# report-only wording, since `rc -ne 0` alone would not catch a regression
# that kept the refusal but mislabelled it.
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$TOOLS_BIN" "$SCRIPT" fake-missing-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "reporting check's tool refusal is not downgraded to 0" \
  || bad "reporting check's tool refusal was downgraded (rc=$rc): $out"
grep -qi "report-only" <<<"$out" \
  && bad "reporting check's tool refusal was printed as an ordinary report-only FAIL: $out" \
  || ok "reporting check's tool refusal is not printed as report-only"

rm -rf "$TOOLS_BIN"

# Step 4(b): a check whose command exits 127 with its declared tools present
# still exits 97 -- the backstop (Step 2), independent of Step 1. No PATH
# restriction needed: RUN_CHECK_FORCE_RC bypasses running the command
# entirely, so this proves the CONVERSION logic, not any particular tool's
# absence (Step 1 is itself skipped whenever RUN_CHECK_FORCE_RC is set --
# see run-check.sh's own comment on that guard).
out=$(CHECKS_FILE="$TOOLS_FIXTURE" RUN_CHECK_FORCE_RC=127 "$SCRIPT" fake-present-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "command exits 127 with tools present: converted to 97" \
  || bad "command exits 127 with tools present: expected rc=97, got rc=$rc: $out"
grep -qi "command not found" <<<"$out" && ok "127-to-97 conversion names \"command not found\"" \
  || bad "127-to-97 conversion did not explain itself: $out"

# ---------------------------------------------------------------------------
# Fix round 1: 99 ("found nothing to examine") must flow through
# run-check.sh's whole-band handling unmolested -- not just proven
# generically via RUN_CHECK_FORCE_RC above (the "exit 97/99 on a reporting
# check still fails the job" loop earlier in this file), but end to end
# through the REAL check-lockfile.sh, genuinely finding zero lockfiles. A
# synthetic checks.yaml (generated here, not committed -- it embeds this
# checkout's own absolute path) whose command `cd`s into a FRESH empty
# directory, created at COMMAND-run time via an unescaped `$(mktemp -d)` in
# the command string, before invoking the real check-lockfile.sh by
# absolute path. This is the concrete scenario fix round 1 named: a check
# running before source is delivered into the capped container (Task 7B's
# gap today) looks exactly like this.
# ---------------------------------------------------------------------------
REAL_LOCKFILE="$HERE/../check-lockfile.sh"
LOCKFILE_INT_FIXTURE="${TMPDIR:-/tmp}/run-check-lockfile-integration.$$.yaml"
cat > "$LOCKFILE_INT_FIXTURE" <<EOF
upstream_tag: v0.28.6
checks:
  - name: fake-lockfile-empty
    upstream: lockfile.yml
    command: cd \$(mktemp -d) && $REAL_LOCKFILE
    compiles: false
    state: reporting
    tools: [jq, find]
EOF

out=$(CHECKS_FILE="$LOCKFILE_INT_FIXTURE" "$SCRIPT" fake-lockfile-empty 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "check-lockfile.sh's own 99 (nothing examined) reaches run-check.sh intact" \
  || bad "expected rc=99 end-to-end through the real check-lockfile.sh, got rc=$rc: $out"
grep -q "^REFUSE fake-lockfile-empty" <<<"$out" \
  && ok "reported as REFUSE, not as an ordinary result" \
  || bad "not reported as REFUSE: $out"
grep -qi "report-only" <<<"$out" \
  && bad "a 'nothing examined' refusal was printed as an ordinary report-only FAIL: $out" \
  || ok "a 'nothing examined' refusal is not printed as report-only"
rm -f "$LOCKFILE_INT_FIXTURE"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
