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

# 1b. A DEGRADED CACHE IS REPORTED IN THE SUMMARY AND CHANGES NOTHING ELSE.
#     Run 573's lesson, from the other side: a dead cache must cost speed,
#     never correctness, and must never quietly become the new normal. So the
#     run stays green, the counters stay at zero, and the summary names it.
out=$(RUN_CHECK_STUB_CACHE_DEAD="check-b" run_with_map "check-a=0 check-b=0 check-c=0" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "a degraded cache does not turn a green run red" \
  || bad "cache degradation changed the exit code (rc=$rc): $out"
grep -q "checks refused: 0, checks failed: 0" <<<"$out" \
  && ok "a degraded cache is counted as neither a refusal nor a failure" \
  || bad "cache degradation moved a counter: $out"
grep -q "cache unavailable on 1 check(s)" <<<"$out" \
  && ok "the run summary names the degradation" \
  || bad "summary is silent about the degraded cache -- it would become invisible: $out"
# Scoped to the SUMMARY BLOCK, not to the whole output. The raw
# CACHE-UNAVAILABLE line is already in the log because the check printed it,
# so a bare `grep "region is missing" <<<"$out"` passes whether or not the
# summary exists -- measured: it survived deleting the summary block outright.
# An assertion that cannot fail for the reason it was written is not a test.
summary_block=$(sed -n '/^cache unavailable on /,$p' <<<"$out")
grep -q "region is missing" <<<"$summary_block" \
  && ok "the summary block itself carries sccache's OWN error, not a paraphrase" \
  || bad "summary block dropped the underlying cause: ${summary_block:-<no summary block>}"
# The count is CHECKS, not marker lines. The fixture emits two lines for one
# check precisely so these can disagree: with a single-line fixture "1 check"
# and "1 line" are the same number and the counter cannot be wrong. It WAS
# wrong -- until 19 Sep this counted lines, so run 576's "5 check(s)" was
# correct only because each check happened to print exactly one line.
[ "$(grep -c '^  CACHE-UNAVAILABLE ' <<<"$summary_block")" -eq 2 ] \
  && ok "the summary block carries every marker line, banner and cause both" \
  || bad "summary block did not carry both lines: ${summary_block:-<no summary block>}"
grep -q "cache unavailable on 1 check(s)" <<<"$summary_block" \
  && ok "the count is checks, not marker lines -- two lines from one check still reads 1" \
  || bad "the summary counted lines and called them checks: ${summary_block:-<no summary block>}"

#     The negative control. Every assertion above would also pass if the
#     summary block printed unconditionally, so a clean run must NOT mention
#     the cache at all.
out=$(run_with_map "check-a=0 check-b=0 check-c=0" 2>&1)
grep -q "cache unavailable" <<<"$out" \
  && bad "summary claims a cache problem on a run that had none: $out" \
  || ok "a healthy run says nothing about the cache"

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

# 4. An ordinary failure THEN a refusal, with nothing after the refusal:
#    true of the current code, and worth keeping, but it does NOT
#    discriminate old from new -- the reviewer reconstructed the pre-fix
#    last-writer-wins loop and ran it against this exact sequence: with the
#    refusal already last, "last write" and "first refusal" agree by
#    coincidence (rc=93 either way). Case 6 below is the version of this
#    ordering that does discriminate: a failure AFTER the refusal too, so
#    last-writer-wins and first-refusal-wins actually disagree.
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

# 6. THE ordering case 4 could not prove: a refusal with an ordinary
#    failure both BEFORE and AFTER it. Last-writer-wins would report the
#    LAST check's code (2) here, not the refusal's (93) -- unlike case 4,
#    where the refusal already being last made the two algorithms agree by
#    accident. This is what actually discriminates "failure, then refusal"
#    from the old code, by giving last-writer-wins one more chance to be
#    wrong after the refusal.
out=$(run_with_map "check-a=1 check-b=93 check-c=2" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "a refusal survives an ordinary failure both before and after it" \
  || bad "a failure after the refusal overwrote it (rc=$rc) -- last-writer-wins is back: $out"
grep -q "checks refused: 1, checks failed: 2" <<<"$out" \
  && ok "counts both surrounding failures plus the one refusal" || bad "counters wrong: $out"

# ---------------------------------------------------------------------------
# Fix round 1 (Task 7A): this script's own enumeration must not be a silent
# zero. `while read ... done < <(python3 list-checks.py ...)` used to hide
# list-checks.py's exit status from the loop entirely -- a checks.yaml that
# failed to load would run zero iterations and report "refused: 0, failed:
# 0" with exit 0, a false green covering the ENTIRE suite. Proven here by
# shadowing list-checks.py with a stub, on a disposable RUN_DIR -- never the
# real list-checks.py or checks.yaml -- exactly the technique
# fixtures/run-check-stub.sh already uses for run-check.sh above.
# ---------------------------------------------------------------------------

# 7. list-checks.py itself fails (simulates a checks.yaml that fails to
#    load): must refuse (99), not report a clean, empty pass.
FAIL_DIR="${TMPDIR:-/tmp}/run-all-checks-enum-fail-test.$$"
mkdir -p "$FAIL_DIR"
ln -sf "$SCRIPT" "$FAIL_DIR/run-all-checks.sh"
ln -sf "$FIXTURES/list-checks-stub-fail.py" "$FAIL_DIR/list-checks.py"
ln -sf "$FIXTURES/run-check-stub.sh" "$FAIL_DIR/run-check.sh"
out=$(CHECKS_FILE="$FIXTURES/checks-three.yaml" "$FAIL_DIR/run-all-checks.sh" 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "an enumeration failure refuses (99), does not report success" \
  || bad "an enumeration failure did not refuse (rc=$rc): $out"
grep -q "checks refused: 0, checks failed: 0" <<<"$out" \
  && bad "an enumeration failure was reported as a clean, empty pass: $out" \
  || ok "an enumeration failure is not reported as a clean, empty pass"
rm -rf "$FAIL_DIR"

# 8. list-checks.py exits 0 but enumerates nothing -- the defence-in-depth
#    positive-count guard, tested independently of the status check above
#    (unreachable through a real checks.yaml, since checks_lib.load()
#    already refuses an empty `checks:` list -- but this task exists
#    specifically to stop trusting "should be unreachable").
EMPTY_DIR="${TMPDIR:-/tmp}/run-all-checks-enum-empty-test.$$"
mkdir -p "$EMPTY_DIR"
ln -sf "$SCRIPT" "$EMPTY_DIR/run-all-checks.sh"
ln -sf "$FIXTURES/list-checks-stub-empty.py" "$EMPTY_DIR/list-checks.py"
ln -sf "$FIXTURES/run-check-stub.sh" "$EMPTY_DIR/run-check.sh"
out=$(CHECKS_FILE="$FIXTURES/checks-three.yaml" "$EMPTY_DIR/run-all-checks.sh" 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "zero checks enumerated (exit 0, no output) refuses (99)" \
  || bad "zero checks enumerated did not refuse (rc=$rc): $out"
grep -q "checks refused: 0, checks failed: 0" <<<"$out" \
  && bad "zero checks enumerated was reported as a clean, empty pass: $out" \
  || ok "zero checks enumerated is not reported as a clean, empty pass"
rm -rf "$EMPTY_DIR"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
