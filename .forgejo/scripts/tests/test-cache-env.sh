#!/usr/bin/env bash
# The distinction this file exists to protect: a COLD cache (nothing to import)
# is normal; a FAILED cache is a build failure. build-image.yml currently treats
# a failed cache export as success, which is how a cache can be dead for days
# while every build reports green.
#
# Fix round 1 finding (measured against real sccache 0.17.0, not a synthetic
# fixture): `sccache --show-stats` never talks to the backend. A completely
# dead bucket produces an all-zero stats blob that is byte-for-byte the shape
# a genuinely first-ever build would also produce if COLD were still the
# default reading. These fixtures are shaped like real sccache output on
# purpose -- including the full field set real sccache always prints -- so a
# script that only handles a trimmed synthetic shape cannot pass by accident.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${CACHE_ENV:-$HERE/../cache-env.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

out=$(S3_ENDPOINT=https://oga2.example:443 "$SCRIPT" warpgate-sccache 2>&1)
grep -q "RUSTC_WRAPPER=sccache"            <<<"$out" && ok "sets the compiler wrapper" || bad "no RUSTC_WRAPPER: $out"
grep -q "SCCACHE_BUCKET=warpgate-sccache"  <<<"$out" && ok "bucket is the one passed"  || bad "wrong bucket: $out"

# Pinned to the exact line, not a substring: "SCCACHE_ENDPOINT=oga2.example" is
# also a substring of "SCCACHE_ENDPOINT=oga2.example:443", so a `grep -q`
# would still pass even if the port were never stripped. This is the
# vacuous-test bug fix round 1's review named.
endpoint_line=$(grep '^SCCACHE_ENDPOINT=' <<<"$out")
[ "$endpoint_line" = "SCCACHE_ENDPOINT=oga2.example" ] \
  && ok "endpoint is the bare host, port stripped" \
  || bad "endpoint line wrong: '$endpoint_line'"

# A credential must never appear, even if one is in the environment.
out=$(S3_ENDPOINT=https://oga2.example:443 AWS_SECRET_ACCESS_KEY=shouldnotappear \
      "$SCRIPT" warpgate-sccache 2>&1)
grep -q "shouldnotappear" <<<"$out" && bad "LEAKED a credential into stdout" \
  || ok "no credential in output"

# A bucket with an embedded newline must not inject an extra KEY=VALUE line
# into the output (env-mode's only output is straight to a workflow's env).
out=$(S3_ENDPOINT=https://oga2.example:443 "$SCRIPT" "$(printf 'warpgate-sccache\nINJECTED=1')" 2>&1); rc=$?
grep -q "^INJECTED=1$" <<<"$out" && bad "a newline in the bucket injected a line: $out" \
  || ok "newline in bucket name cannot inject a line"
[ $rc -ne 0 ] && ok "newline in bucket name is refused (exit $rc)" || bad "newline in bucket name was silently accepted"

# --- Verdicts -----------------------------------------------------------
# Every fixture below carries the full field set real sccache 0.17.0 prints
# on every `--show-stats` call (confirmed locally against both a working
# local-disk backend and an unreachable S3 endpoint, dummy credentials only,
# `SCCACHE_SERVER_PORT` isolated from any other build on this host). A
# fixture missing a field real sccache never omits is not standing in for
# real sccache -- see the fail-closed block below for what that must do.

# A genuine first-ever build: compiles ran, the backend answered, nothing to
# reuse yet. This is what COLD actually looks like -- misses > 0, not the
# all-zero blob the original round-1 fixture used.
cold_real='Compile requests                      1
Compile requests executed             1
Cache hits                            0
Cache misses                          1
Cache hits rate                    0.00 %
Cache timeouts                        0
Cache read errors                     0
Forced recaches                       0
Cache write errors                    0
Cache errors                          0'

warm_real='Compile requests                      2
Compile requests executed             2
Cache hits                            1
Cache hits rate                   50.00 %
Cache misses                          1
Cache timeouts                        0
Cache read errors                     0
Forced recaches                       0
Cache write errors                    0
Cache errors                          0'

# Partial failure: compiles ran and some hit, but the backend is also
# throwing errors. Errors outrank a WARM-looking hit count.
degraded='Compile requests                     50
Compile requests executed            50
Cache hits                            2
Cache misses                         10
Cache timeouts                        0
Cache read errors                     3
Forced recaches                       0
Cache write errors                    5
Cache errors                          8'

# The dead-backend fingerprint measured for real: every field present (real
# sccache never omits one), every field zero, INCLUDING compile requests.
# This is what an unreachable bucket looks like from `--show-stats` alone --
# indistinguishable from cold_real's shape unless compile requests is also
# checked, which is exactly why it is checked.
dead_backend='Compile requests                      0
Compile requests executed             0
Cache hits                            0
Cache misses                          0
Cache hits rate                       -
Cache timeouts                        0
Cache read errors                     0
Forced recaches                       0
Cache write errors                    0
Cache errors                          0'

v=$("$SCRIPT" --verdict "$cold_real"); rc=$?
[ "$v" = "COLD" ] && [ $rc -eq 0 ] && ok "real first-build shape reads COLD and passes" || bad "cold_real -> $v rc=$rc"
v=$("$SCRIPT" --verdict "$warm_real"); rc=$?
[ "$v" = "WARM" ] && [ $rc -eq 0 ] && ok "a real hit reads WARM" || bad "warm_real -> $v rc=$rc"
v=$("$SCRIPT" --verdict "$degraded"); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] && ok "errors outrank hits: still FAILED" \
  || bad "degraded cache did not fail the build (v=$v rc=$rc)"
v=$("$SCRIPT" --verdict "$dead_backend"); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] \
  && ok "0 compile requests (dead backend) reads FAILED, not COLD -- this is the fix round 1 bug" \
  || bad "dead backend did not fail the build (v=$v rc=$rc)"

# The negative that matters: a genuinely cold cache and a dead one must not
# be the same answer, even though `--show-stats` alone cannot tell them apart.
[ "$("$SCRIPT" --verdict "$cold_real")" != "$("$SCRIPT" --verdict "$dead_backend")" ] \
  && ok "cold and dead-backend are distinguished" \
  || bad "cold and dead-backend collapse to one verdict -- the whole point of this file"

# sccache's own account of its startup outranks the counters, even when the
# rest of the blob claims a healthy WARM shape (e.g. stray output got
# concatenated ahead of a real stats dump). Real error text captured from
# sccache 0.17.0 against an unreachable endpoint.
marker_blob='sccache: error: Server startup failed: cache storage failed to read: Unexpected (temporary) at read => send http request
Compile requests                     10
Compile requests executed            10
Cache hits                            5
Cache misses                          5
Cache timeouts                        0
Cache read errors                     0
Forced recaches                       0
Cache write errors                    0
Cache errors                          0'
v=$("$SCRIPT" --verdict "$marker_blob"); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] \
  && ok "sccache's own startup-failure marker overrides healthy-looking counters" \
  || bad "startup-failure marker was ignored (v=$v rc=$rc)"

# Fail closed: no evidence must never be read as good news.
v=$("$SCRIPT" --verdict ""); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] && ok "empty stats blob reads FAILED, not COLD" \
  || bad "empty blob -> $v rc=$rc"

v=$("$SCRIPT" --verdict); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] && ok "no stats argument at all reads FAILED" \
  || bad "missing argument -> $v rc=$rc"

v=$("$SCRIPT" --verdict "not sccache output at all, just noise"); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] && ok "unparseable blob reads FAILED" \
  || bad "garbage blob -> $v rc=$rc"

# A blob missing exactly one field real sccache never omits (Cache errors,
# here) must fail closed rather than default that field to 0.
missing_field='Compile requests                      1
Compile requests executed             1
Cache hits                            0
Cache misses                          1
Cache timeouts                        0
Cache read errors                     0
Forced recaches                       0
Cache write errors                    0'
v=$("$SCRIPT" --verdict "$missing_field"); rc=$?
[ "$v" = "FAILED" ] && [ $rc -eq 1 ] \
  && ok "a blob missing an expected field reads FAILED, not a guessed default" \
  || bad "missing_field -> $v rc=$rc"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
