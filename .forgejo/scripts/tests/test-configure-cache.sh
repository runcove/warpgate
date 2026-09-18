#!/usr/bin/env bash
# configure-cache.sh wraps cache-env.sh's load-bearing exit status (Task 3):
# on refusal cache-env.sh prints nothing, and appending nothing to
# $GITHUB_ENV "succeeds" exactly as quietly as a real bucket would. These
# tests prove the refusal path is loud (a warning, on stdout) and inert
# (nothing written to $GITHUB_ENV), and the success path actually populates
# it -- the negative path the Task 5 review flagged as verified only in a
# scratch file, now committed (review finding 3).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${CONFIGURE_CACHE:-$HERE/../configure-cache.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

SCRATCH="${TMPDIR:-/tmp}/configure-cache-test.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

# 1. Refusal (missing S3_ENDPOINT): loud, non-fatal, GITHUB_ENV untouched.
GENV="$SCRATCH/refusal.env"
out=$(unset S3_ENDPOINT; GITHUB_ENV="$GENV" "$SCRIPT" warpgate-sccache 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "a cache-env.sh refusal does not fail this step" \
  || bad "refusal failed the step (rc=$rc): $out"
grep -q "::warning::" <<<"$out" && ok "the refusal is reported loudly (a warning)" \
  || bad "refusal was silent: $out"
grep -qi "S3_ENDPOINT" <<<"$out" && ok "names the actual missing configuration" \
  || bad "did not say why: $out"
[ ! -e "$GENV" ] && ok "GITHUB_ENV is never touched on a refusal" \
  || bad "GITHUB_ENV was written despite the refusal: $(cat "$GENV")"

# 2. Success: GITHUB_ENV gets all five KEY=VALUE lines, exactly once, and
#    nothing is silently dropped.
GENV="$SCRATCH/success.env"
out=$(S3_ENDPOINT=https://oga2.example:443 GITHUB_ENV="$GENV" "$SCRIPT" warpgate-sccache 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "success exits 0" || bad "success path failed (rc=$rc): $out"
grep -q "compiler cache configured" <<<"$out" && ok "says it configured the cache" \
  || bad "silent about success: $out"
for kv in RUSTC_WRAPPER=sccache SCCACHE_BUCKET=warpgate-sccache SCCACHE_ENDPOINT=oga2.example \
          SCCACHE_S3_USE_SSL=true SCCACHE_S3_NO_CREDENTIALS=0; do
  grep -qx "$kv" "$GENV" && ok "GITHUB_ENV carries $kv" || bad "GITHUB_ENV missing $kv: $(cat "$GENV" 2>/dev/null)"
done

# 3. GITHUB_ENV entirely unset (not just pointed at a scratch file) must not
#    crash -- that is a real state outside CI (running this by hand), not a
#    refusal.
out=$(unset GITHUB_ENV; S3_ENDPOINT=https://oga2.example:443 "$SCRIPT" warpgate-sccache 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "runs fine with GITHUB_ENV entirely unset" \
  || bad "crashed or failed with GITHUB_ENV unset (rc=$rc): $out"

# 4. A missing bucket argument is a caller error, not a silent success.
out=$("$SCRIPT" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok "a missing bucket argument is refused, not silently accepted" \
  || bad "ran with no bucket argument"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
