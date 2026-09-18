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
for code in 89 90 91 92 93 95 99; do
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
# check that was told, via the test hooks, to report PASS.
out=$(RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=90 "$SCRIPT" clippy 2>&1); rc=$?
[ $rc -ne 0 ] && ok "a refusal fails a blocking check too" \
  || bad "a refusal passed a blocking check (rc=$rc): $out"

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

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
