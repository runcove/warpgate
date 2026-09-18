#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${RUN_CHECK:-$HERE/../run-check.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

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

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
