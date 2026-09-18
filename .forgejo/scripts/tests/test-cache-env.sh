#!/usr/bin/env bash
# The distinction this file exists to protect: a COLD cache (nothing to import)
# is normal; a FAILED cache is a build failure. build-image.yml currently treats
# a failed cache export as success, which is how a cache can be dead for days
# while every build reports green.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${CACHE_ENV:-$HERE/../cache-env.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

out=$(S3_ENDPOINT=https://oga2.example:443 "$SCRIPT" warpgate-sccache 2>&1)
grep -q "RUSTC_WRAPPER=sccache"            <<<"$out" && ok "sets the compiler wrapper" || bad "no RUSTC_WRAPPER: $out"
grep -q "SCCACHE_BUCKET=warpgate-sccache"  <<<"$out" && ok "bucket is the one passed"  || bad "wrong bucket: $out"
grep -q "SCCACHE_ENDPOINT=oga2.example"    <<<"$out" && ok "endpoint from env"         || bad "no endpoint: $out"

# A credential must never appear, even if one is in the environment.
out=$(S3_ENDPOINT=https://oga2.example:443 AWS_SECRET_ACCESS_KEY=shouldnotappear \
      "$SCRIPT" warpgate-sccache 2>&1)
grep -q "shouldnotappear" <<<"$out" && bad "LEAKED a credential into stdout" \
  || ok "no credential in output"

# Verdicts.
cold='Cache hits  0
Cache misses  0
Cache errors  0'
warm='Cache hits  812
Cache misses  40
Cache errors  0'
failed='Cache hits  0
Cache misses  40
Cache errors  40'

v=$("$SCRIPT" --verdict "$cold");   rc=$?
[ "$v" = "COLD" ] && [ $rc -eq 0 ] && ok "empty cache reads COLD and passes" || bad "cold -> $v rc=$rc"
v=$("$SCRIPT" --verdict "$warm");   rc=$?
[ "$v" = "WARM" ] && [ $rc -eq 0 ] && ok "populated cache reads WARM"        || bad "warm -> $v rc=$rc"
v=$("$SCRIPT" --verdict "$failed"); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] && ok "erroring cache reads FAILED and fails" \
  || bad "errors did not fail the build (v=$v rc=$rc) -- this is the current bug"

# The negative that matters: COLD and FAILED must not be the same answer.
[ "$("$SCRIPT" --verdict "$cold")" != "$("$SCRIPT" --verdict "$failed")" ] \
  && ok "cold and failed are distinguished" \
  || bad "cold and failed collapse to one verdict -- the whole point of this file"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
