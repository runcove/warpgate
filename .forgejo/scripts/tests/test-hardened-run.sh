#!/usr/bin/env bash
# The cap assertion is the whole point of this script. These tests exist to prove
# it FAILS when the cap is absent -- a cap that is merely requested and never
# verified is what upstream has, and it is what let a build take the cluster down.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${HARDENED_RUN:-$HERE/../hardened-run.sh}"
fails=0
ok()   { echo "  ok    $1"; }
bad()  { echo "  FAIL  $1"; fails=1; }

# 1. The invocation carries the caps we asked for.
out=$(HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1)
grep -q -- "--cpus=4"   <<<"$out" && ok "cpu cap appears in the invocation"   || bad "cpu cap missing: $out"
grep -q -- "--memory=7g" <<<"$out" && ok "memory cap appears in the invocation" || bad "memory cap missing: $out"

# 2. Memory-swap must equal memory. Without it the container swaps instead of
#    being killed, and the cap silently does not bound anything.
grep -q -- "--memory-swap=7g" <<<"$out" && ok "memory-swap pinned to memory" \
  || bad "memory-swap not pinned -- the cap does not bound the build: $out"

# 3. A missing cap argument is refused outright rather than defaulted.
"$SCRIPT" --cpus 4 -- true >/dev/null 2>&1
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

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
