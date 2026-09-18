#!/usr/bin/env bash
# Configure the compiler cache for capped/compiling checks (best-effort).
#
# cache-env.sh's own exit status is load-bearing (Task 3): on refusal it
# prints nothing, and appending nothing to $GITHUB_ENV "succeeds" exactly as
# quietly as a real bucket would -- the compiling checks would then just run
# without a cache, with no line anywhere saying why. This captures output
# and rc separately and trusts the output only once rc is 0.
#
# A refusal here does not fail the run: the cache is what makes eleven
# checks on one runner affordable, not what makes them correct, so this
# warns loudly and the checks still run, capped, just uncached.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BUCKET="${1:?usage: configure-cache.sh <bucket>}"

out=$("$HERE/cache-env.sh" "$BUCKET" 2>&1) || rc=$?
rc="${rc:-0}"
if [ "$rc" -ne 0 ]; then
  echo "::warning::cache-env.sh refused (exit $rc) -- compiling checks run uncached this time, not unsafely: still CPU/memory-capped, just slower."
  echo "$out"
else
  # GITHUB_ENV may be unset outside real CI (e.g. this script run by hand or
  # by a test) -- that is not a refusal, just nowhere to persist the vars.
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "$out" >> "$GITHUB_ENV"
  fi
  echo "compiler cache configured: bucket $BUCKET"
fi
exit 0
