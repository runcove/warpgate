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

# FIX ROUND 1 ADDENDUM: a missing required input is a refusal (93), not an
# ordinary exit 1 indistinguishable from any other failure -- same defect,
# same fix, as hardened-run.sh's HARDENED_RUN_IMAGE case and run-check.sh's
# missing check-name case.
out=$("$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "missing bucket argument exits 93, not a bare 1" \
  || bad "missing bucket argument did not exit 93 (rc=$rc): $out"

out=$(unset S3_ENDPOINT; "$SCRIPT" warpgate-sccache 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "missing S3_ENDPOINT exits 93, not a bare 1" \
  || bad "missing S3_ENDPOINT did not exit 93 (rc=$rc): $out"
# NOT `grep -qi "S3_ENDPOINT"` -- bash's own pre-fix `${VAR:?}` error
# ("...: line N: S3_ENDPOINT: S3_ENDPOINT must be set") ALSO mentions the
# variable name (it's the same custom :? message this fix's own text
# happens to reuse), so that grep alone survives the very mutation it
# exists to catch. Anchor to the "FATAL --" prefix only this script's own
# refusal message produces.
grep -q "cache-env.sh: FATAL -- S3_ENDPOINT must be set" <<<"$out" \
  && ok "names the missing configuration in our own refusal message, not bash's builtin :? text" \
  || bad "did not produce our own refusal message: $out"

# THE TRAP THIS MATTERS FOR: `eval "$(cache-env.sh ...)"` of a refusal that
# printed nothing still `eval`s to success (exit 0), so a caller checking
# only "did eval fail" would never see this. Confirm the refusal itself
# prints no partial KEY=VALUE line an eval could pick up.
out=$(unset S3_ENDPOINT; "$SCRIPT" warpgate-sccache 2>/dev/null)
[ -z "$out" ] && ok "no partial KEY=VALUE output leaks out on refusal" \
  || bad "refusal still printed output an eval would pick up: $out"

out=$(S3_ENDPOINT=https://oga2.example:9000 "$SCRIPT" warpgate-sccache 2>&1)
grep -q "RUSTC_WRAPPER=sccache"            <<<"$out" && ok "sets the compiler wrapper" || bad "no RUSTC_WRAPPER: $out"

# SCCACHE_REGION is REQUIRED by sccache's S3 backend, and its absence cost
# run 573: sccache refused to start with "region is missing", which — because
# RUSTC_WRAPPER fronts every rustc call — turned unit-tests and sbom from PASS
# into FAIL and schema-compat from a known FAIL into REFUSE 96. A broken cache
# was strictly worse than no cache.
#
# `auto` rather than an AWS region name, per sccache v0.17.0 docs/S3.md: the
# region "can be set to `auto` if using a custom endpoint", and region
# detection means nothing against a non-AWS store like QuObjects. Pinned to
# the exact line so substituting a plausible-looking region such as us-east-1
# is caught — it might even work, and "might work" is not what this file is
# for.
region_line=$(grep '^SCCACHE_REGION=' <<<"$out")
[ "$region_line" = "SCCACHE_REGION=auto" ] \
  && ok "sets SCCACHE_REGION=auto (required; sccache will not start without it)" \
  || bad "expected SCCACHE_REGION=auto, got '${region_line:-<absent>}': $out"

# The whole emitted set, pinned as a set. Each line above checks one variable
# it already knows to look for, so a newly-required variable going missing is
# invisible to all of them — which is exactly how the region was lost. This
# fails when a variable is dropped AND when one is added without a decision.
got_keys=$(cut -d= -f1 <<<"$out" | sort | tr '\n' ' ')
want_keys="RUSTC_WRAPPER SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION SCCACHE_S3_NO_CREDENTIALS SCCACHE_S3_USE_SSL "
[ "$got_keys" = "$want_keys" ] \
  && ok "emits exactly the six expected variables, no more and no fewer" \
  || bad "emitted set changed: got [$got_keys] want [$want_keys]"
grep -q "SCCACHE_BUCKET=warpgate-sccache"  <<<"$out" && ok "bucket is the one passed"  || bad "wrong bucket: $out"

# THE FIXTURE IS THE TEST HERE, and it used to be the bug.
#
# This case drove `:443` until 2026-09-19 and asserted the port was STRIPPED.
# The assertion was pinned to the exact line rather than a substring, with a
# comment explaining why — all of which was correct and none of which helped,
# because :443 is the ONE port at which stripping and keeping produce the same
# WORKING result. A precisely-argued assertion built on the single input value
# where the behaviour under test cannot do any harm. Our real endpoint is
# QuObjects on :8010, where the two differ completely: measured that day,
# oga2.tenfourty.site:8010 is open and :443 is closed.
#
# So the fixture now uses a NON-DEFAULT port, and the expectation is inverted
# to match sccache 0.17.0's documented form (`SCCACHE_ENDPOINT=<ip>:<port>`).
# With :9000, "stripped" and "kept" are different observable strings, so this
# assertion can now fail for the reason it exists.
endpoint_line=$(grep '^SCCACHE_ENDPOINT=' <<<"$out")
[ "$endpoint_line" = "SCCACHE_ENDPOINT=oga2.example:9000" ] \
  && ok "a non-default port is PRESERVED, as sccache documents" \
  || bad "endpoint line wrong: '$endpoint_line' (expected the port to survive)"

# The scheme must still go, and a trailing path with it — sccache takes the
# protocol from SCCACHE_S3_USE_SSL, and the endpoint is a host, not a URL.
for e in "https://oga2.example:9000" "http://oga2.example:9000" "oga2.example:9000" "https://oga2.example:9000/"; do
  line=$(S3_ENDPOINT="$e" "$SCRIPT" warpgate-sccache 2>&1 | grep '^SCCACHE_ENDPOINT=')
  [ "$line" = "SCCACHE_ENDPOINT=oga2.example:9000" ] \
    && ok "scheme/path stripped, port kept: $e" \
    || bad "from '$e' got '$line'"
done

# :443 kept as a REGRESSION case, but only now that a discriminating one sits
# above it. On its own it proved nothing; beside :9000 it confirms the default
# port is not special-cased into disappearing.
line=$(S3_ENDPOINT=https://oga2.example:443 "$SCRIPT" warpgate-sccache 2>&1 | grep '^SCCACHE_ENDPOINT=')
[ "$line" = "SCCACHE_ENDPOINT=oga2.example:443" ] \
  && ok "the default port is kept too, not special-cased away" \
  || bad "443 case: got '$line'"

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
