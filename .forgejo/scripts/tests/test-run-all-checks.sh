#!/usr/bin/env bash
# run-all-checks.sh decides the job's own exit code from every check's
# result. The property under test is ordering: a refusal (89-99) is a
# different fact from an ordinary failure ("did not run safely" vs. "ran and
# failed"), so the FIRST refusal must survive anything that runs after it --
# another refusal with a different code, or an ordinary failure -- and must
# not itself be replaced by a later refusal either. Driven by a stub
# run-check.sh (fixtures/run-check-stub.sh) via RUN_CHECK_STUB_MAP, against
# a 3-check synthetic list (fixtures/checks-three.yaml): no real check
# commands, no hardened-run.sh, no container runtime anywhere in this test.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${RUN_ALL_CHECKS:-$HERE/../run-all-checks.sh}"
FIXTURES="$HERE/fixtures"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

RUN_DIR="${TMPDIR:-/tmp}/run-all-checks-test.$$"
mkdir -p "$RUN_DIR"
ln -sf "$SCRIPT" "$RUN_DIR/run-all-checks.sh"
ln -sf "$HERE/../list-checks.py" "$RUN_DIR/list-checks.py"
ln -sf "$FIXTURES/run-check-stub.sh" "$RUN_DIR/run-check.sh"
trap 'rm -rf "$RUN_DIR"' EXIT

run_with_map() {
  CHECKS_FILE="$FIXTURES/checks-three.yaml" RUN_CHECK_STUB_MAP="$1" "$RUN_DIR/run-all-checks.sh"
}

# 1. All pass: exit 0, both counters 0.
out=$(run_with_map "check-a=0 check-b=0 check-c=0" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "all-pass run exits 0" || bad "all-pass run did not exit 0 (rc=$rc): $out"
grep -q "checks refused: 0, checks failed: 0" <<<"$out" \
  && ok "reports zero refused and zero failed" || bad "counters wrong: $out"

# 2. A lone ordinary failure (not a refusal) sets the job's exit code.
out=$(run_with_map "check-a=0 check-b=1 check-c=0" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "a lone ordinary failure sets the job's exit code" \
  || bad "lone failure did not set rc=1 (rc=$rc): $out"
grep -q "checks refused: 0, checks failed: 1" <<<"$out" \
  && ok "counts it as failed, not refused" || bad "counters wrong: $out"

# 3. THE case that means something (fix-round brief): a refusal followed by
#    an ordinary failure must exit with the REFUSAL's code, not the later
#    failure's.
out=$(run_with_map "check-a=93 check-b=1 check-c=0" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "a refusal followed by an ordinary failure exits with the refusal's code" \
  || bad "the later ordinary failure overwrote the refusal (rc=$rc): $out"
grep -q "checks refused: 1, checks failed: 1" <<<"$out" \
  && ok "counts one refused and one failed, distinctly" || bad "counters wrong: $out"

# 4. Same property, reversed order: an ordinary failure THEN a refusal must
#    still end on the refusal -- order must not change the outcome.
out=$(run_with_map "check-a=1 check-b=93 check-c=0" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "a refusal after an ordinary failure still wins" \
  || bad "the refusal did not win when it came second (rc=$rc): $out"

# 5. Two DIFFERENT refusals: the FIRST refusal's code wins, not the second's
#    -- "first refusal wins", not "last write wins" applied to refusals too.
out=$(run_with_map "check-a=93 check-b=90 check-c=0" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "the first refusal's code wins over a second, different refusal" \
  || bad "a later refusal overwrote the first (rc=$rc): $out"
grep -q "checks refused: 2, checks failed: 0" <<<"$out" \
  && ok "counts both refusals" || bad "counters wrong: $out"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
