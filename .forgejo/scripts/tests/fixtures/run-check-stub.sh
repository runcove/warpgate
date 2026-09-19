#!/usr/bin/env bash
# Stub run-check.sh: returns a per-check exit code from a caller-supplied
# mapping (RUN_CHECK_STUB_MAP, space-separated NAME=CODE pairs), so
# run-all-checks.sh's ordering logic (first refusal wins) can be tested
# against a MIXED refusal/failure run without real check commands,
# hardened-run.sh, or a container runtime anywhere in the loop.
set -uo pipefail
name="${1:?usage: run-check-stub.sh <name>}"
code=0
for pair in ${RUN_CHECK_STUB_MAP:-}; do
  n="${pair%%=*}"
  c="${pair#*=}"
  if [ "$n" = "$name" ]; then code="$c"; fi
done

# Emits the cache-degraded marker for the named checks, so run-all-checks.sh's
# collection of it can be tested without sccache, a bucket or a container.
# The real marker is written inside the capped container by run-check.sh's
# CACHE_PROBE; what run-all-checks.sh sees either way is a line on the check's
# output, which is exactly what this reproduces.
# TWO lines, banner first, because that is the shape the real probe emits and
# the shape that defeated the old single-line version in run 576. A one-line
# fixture cannot tell "collects every marker" from "collects the first marker",
# so the summary could drop the cause and this suite would stay green.
for n in ${RUN_CHECK_STUB_CACHE_DEAD:-}; do
  if [ "$n" = "$name" ]; then
    echo "CACHE-UNAVAILABLE $name — sccache: Starting the server..." >&2
    echo "CACHE-UNAVAILABLE $name — sccache: error: Server startup failed: region is missing" >&2
  fi
done

# And the POSITIVE reading, same reasoning in the other direction. The real
# CACHE-STATS line is written by an EXIT trap inside the capped container; what
# run-all-checks.sh sees is a line on the check's output, reproduced here.
# TWO lines again, because the real marker emits an explanatory second line
# when hits are zero -- a one-line fixture could not tell "collects every
# reading" from "collects the first".
for n in ${RUN_CHECK_STUB_CACHE_STATS:-}; do
  if [ "$n" = "$name" ]; then
    echo "CACHE-STATS $name — requests=772 executed=765 hits=765 misses=7 rate=99.09 % compilations=7 read-errors=0 write-errors=0 errors=0 avg-read-hit=0.167 s" >&2
    echo "CACHE-STATS $name — second line, to prove every reading is collected rather than the first" >&2
  fi
done

# The no-reading case, which must NOT be filed as a reading.
for n in ${RUN_CHECK_STUB_CACHE_STATS_GONE:-}; do
  if [ "$n" = "$name" ]; then
    echo "CACHE-STATS-UNAVAILABLE $name — sccache --show-stats produced nothing at the end of the check" >&2
  fi
done

if [ "$code" -ge 89 ] && [ "$code" -le 99 ]; then
  echo "REFUSE $name — did not run safely (exit $code, reserved band 89-99)." >&2
elif [ "$code" -eq 0 ]; then
  echo "PASS $name"
else
  echo "FAIL $name — exit $code" >&2
fi
exit "$code"
