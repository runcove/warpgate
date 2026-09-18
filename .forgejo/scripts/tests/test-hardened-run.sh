#!/usr/bin/env bash
# The cap assertion is the whole point of this script. These tests exist to prove
# it FAILS when the cap is absent -- a cap that is merely requested and never
# verified is what upstream has, and it is what let a build take the cluster down.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${HARDENED_RUN:-$HERE/../hardened-run.sh}"
FIXTURES="$HERE/fixtures"
fails=0
ok()   { echo "  ok    $1"; }
bad()  { echo "  FAIL  $1"; fails=1; }

# Cases 1-11 drive hardened-run.sh's own test hooks (HARDENED_RUN_DRY,
# HARDENED_RUN_FAKE_INSPECT*), which fix round 1 makes fatal to use inside a
# real CI run (see cases 12-14). Clear any ambient CI markers so this suite
# keeps working when it is itself run as a check under real Forgejo Actions.
unset CI GITHUB_ACTIONS FORGEJO_ACTIONS

# Scratch dir for "did docker exec actually run" marker files. Not mktemp
# (blocked in this environment) -- a PID-suffixed dir under TMPDIR, same
# pattern a real CI runner's own tmp would give it.
MARKER_DIR="${TMPDIR:-/tmp}/hardened-run-test.$$"
mkdir -p "$MARKER_DIR"
trap 'rm -rf "$MARKER_DIR"' EXIT

# 1. The invocation carries the caps we asked for.
out=$(HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1)
grep -q -- "--cpus=4"   <<<"$out" && ok "cpu cap appears in the invocation"   || bad "cpu cap missing: $out"
grep -q -- "--memory=7g" <<<"$out" && ok "memory cap appears in the invocation" || bad "memory cap missing: $out"

# 2. Memory-swap must equal memory. Without it the container swaps instead of
#    being killed, and the cap silently does not bound anything.
grep -q -- "--memory-swap=7g" <<<"$out" && ok "memory-swap pinned to memory" \
  || bad "memory-swap not pinned -- the cap does not bound the build: $out"

# 3. A missing cap argument is refused outright rather than defaulted.
#    HARDENED_RUN_IMAGE is exported and a stub `docker` put on PATH so that,
#    if the memory-required guard is ever deleted, this case fails for THAT
#    reason -- not because `${HARDENED_RUN_IMAGE:?}` or a missing `docker`
#    binary dies first, both of which used to make this case pass "ok" even
#    with the guard gone (fix round 1, finding 3).
(
  export PATH="$FIXTURES:$PATH"
  export HARDENED_RUN_IMAGE=stub-image
  export STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000
  "$SCRIPT" --cpus 4 -- true >/dev/null 2>&1
)
[ $? -ne 0 ] && ok "refuses to run without a memory cap" \
  || bad "ran with no memory cap -- this is the 2026-09-15 incident"

# 4. THE NEGATIVE THAT MAKES THE REST MEAN ANYTHING: when the runtime reports a
#    cap of 0 (i.e. no cap took effect), the script must exit 90, not succeed.
out=$(HARDENED_RUN_DRY=1 HARDENED_RUN_FAKE_INSPECT=0 \
      "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 when the runtime reports no cap" \
  || bad "did not fail on an absent cap (rc=$rc) -- the assertion is decorative"
grep -qi "cap" <<<"$out" && ok "says what went wrong" || bad "failed silently"

# 5. A cap that IS present must not trip the assertion.
HARDENED_RUN_DRY=1 HARDENED_RUN_FAKE_INSPECT=7516192768 \
  "$SCRIPT" --cpus 4 --memory 7g -- true >/dev/null 2>&1
[ $? -eq 0 ] && ok "passes when the cap is really in place" \
  || bad "false alarm on a good cap"

# 6. Nothing Warpgate-specific (spec ruling 2: this must generalise).
if grep -qi "warpgate" "$SCRIPT"; then
  bad "contains 'warpgate' -- it is supposed to be reusable by cove and ch"
else ok "no repo-specific content"; fi

# 7-11. FIX ROUND 1, finding 1: the wrapper must tell "capped" from "could not
# tell", exercised through a stub `docker` on PATH so the real (non-dry)
# inspect path actually runs -- HARDENED_RUN_DRY/HARDENED_RUN_FAKE_INSPECT
# never reach this code at all.

# 7. An inspect that fails outright must not let the command run. Before the
#    fix, a failed `docker inspect` was silently swallowed (`2>/dev/null`),
#    producing an empty ACTUAL that skipped the "== 0" check and fell
#    through to `docker exec`. Reproduced by the reviewer with this exact
#    stub.
marker="$MARKER_DIR/exec-ran-7"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_INSPECT_RC=1 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 when docker inspect itself fails" \
  || bad "did not exit 90 on a failed inspect (rc=$rc): $out"
grep -qi "cap" <<<"$out" && ok "names the cap when inspect fails" || bad "failed silently: $out"
[ ! -e "$marker" ] && ok "the command never ran after a failed inspect" \
  || bad "docker exec ran despite a failed inspect -- the assertion is decorative"

# 8. A non-numeric inspect result must not let the command run either.
marker="$MARKER_DIR/exec-ran-8"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM="<none>" STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 on a non-numeric inspect result" \
  || bad "did not exit 90 on garbage inspect output (rc=$rc): $out"
[ ! -e "$marker" ] && ok "the command never ran after a garbage inspect" \
  || bad "docker exec ran despite a garbage inspect result"

# 9. A numeric cap that is merely WRONG -- not literally "0" -- must also
#    refuse. The old check only ever compared against the string "0", so a
#    runtime silently capping at, say, half of what was asked would have
#    sailed straight through it.
marker="$MARKER_DIR/exec-ran-9"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=1073741824 STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 when the runtime's cap doesn't match what was requested" \
  || bad "accepted a mismatched cap (rc=$rc): $out"
[ ! -e "$marker" ] && ok "the command never ran with a mismatched cap" \
  || bad "docker exec ran despite a mismatched cap"

# 10. Asking for 0 and getting 0 back must still refuse. A pure "actual ==
#     expected" comparison would treat this as consistent; docker's own
#     semantics say a cap of 0 always means "no cap took effect", regardless
#     of what was requested, so that reading must be checked unconditionally
#     and not just as one side of an equality test. (Found via the fix-3
#     deletion mutant below, which showed exactly this gap before this case
#     existed.)
marker="$MARKER_DIR/exec-ran-10"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=0 STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 0 -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "refuses even when 0 was requested and 0 came back" \
  || bad "accepted a requested-and-actual cap of 0 (rc=$rc): $out"
[ ! -e "$marker" ] && ok "the command never ran with a 0/0 cap" \
  || bad "docker exec ran despite a 0/0 cap"

# 11. Sanity: a real run where both caps genuinely match must still succeed
#     and actually run the command -- fix 1 must not turn this into a
#     wrapper that never runs anything.
marker="$MARKER_DIR/exec-ran-11"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 0 ] && ok "a genuinely correct real cap still succeeds" \
  || bad "false alarm on a real, correct cap (rc=$rc): $out"
[ -e "$marker" ] && ok "the command actually ran when the cap was correct" \
  || bad "the command never ran even though the cap was correct"

# 12-14. FIX ROUND 1, finding 2: a leaked test hook must fail loudly under
# CI, not run silently as a no-op.

# 12. HARDENED_RUN_DRY alone would otherwise turn a real build step into a
#     green no-op if it leaked in via a copied env: block or a prior step's
#     GITHUB_ENV.
out=$(CI=true HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses a leaked HARDENED_RUN_DRY under CI" \
  || bad "did not refuse HARDENED_RUN_DRY under CI (rc=$rc): $out"
grep -q "HARDENED_RUN_DRY" <<<"$out" && ok "names HARDENED_RUN_DRY as the offender" \
  || bad "did not name the offending variable: $out"

# 13. Same for HARDENED_RUN_FAKE_INSPECT, which alone makes the script
#     report success without ever calling docker run or docker inspect.
out=$(GITHUB_ACTIONS=true HARDENED_RUN_FAKE_INSPECT=7516192768 \
      "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses a leaked HARDENED_RUN_FAKE_INSPECT under CI" \
  || bad "did not refuse HARDENED_RUN_FAKE_INSPECT under CI (rc=$rc): $out"
grep -q "HARDENED_RUN_FAKE_INSPECT" <<<"$out" && ok "names HARDENED_RUN_FAKE_INSPECT as the offender" \
  || bad "did not name the offending variable: $out"

# 14. Not named in the brief's wording of fix 2, but the same leak would
#     defeat the same guard for the CPU-side fake hook fix 1 adds alongside
#     the existing memory one, so it gets the same treatment.
out=$(FORGEJO_ACTIONS=true HARDENED_RUN_FAKE_INSPECT_CPUS=4000000000 \
      "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses a leaked HARDENED_RUN_FAKE_INSPECT_CPUS under CI" \
  || bad "did not refuse HARDENED_RUN_FAKE_INSPECT_CPUS under CI (rc=$rc): $out"
grep -q "HARDENED_RUN_FAKE_INSPECT_CPUS" <<<"$out" && ok "names HARDENED_RUN_FAKE_INSPECT_CPUS as the offender" \
  || bad "did not name the offending variable: $out"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
