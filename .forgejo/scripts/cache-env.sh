#!/usr/bin/env bash
# sccache configuration, and the verdict that tells a cold cache from a broken one.
#
# Upstream caches with GitHub services (Swatinem/rust-cache, type=gha) which do
# not exist on our forge, so none of it is inheritable. This is an addition to
# upstream's approach, not an adoption of it.
#
# --verdict's input contract: pass whatever text you have -- sccache's own
# stderr from the build (or probe) that produced it, concatenated with the
# output of `sccache --show-stats`, in either order. `--show-stats` alone
# cannot tell a cold cache from a dead one: it never talks to the backend, so
# a bucket that has been unreachable since the server last (re)started still
# prints an honest, all-zero, "nothing cached yet"-shaped blob. Measured
# against real sccache 0.17.0 pointed at an unreachable endpoint: the actual
# compile fails with "sccache: error: Server startup failed: cache storage
# failed to read: ..." (exit 2), and a following `--show-stats` still exits 0
# with every counter, including compile requests, at zero -- indistinguishable
# from a genuine first build unless compile requests is also checked. That is
# why sccache's own account of its startup, wherever it appears in the blob,
# outranks every counter below.
set -uo pipefail

if [ "${1:-}" = "--verdict" ]; then
  stats="${2:-}"

  # Nothing to read at all.
  if [ -z "$stats" ]; then
    echo "cache-env.sh: no cache stats given -- cannot tell, treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # sccache's own account of its startup outranks every counter below: a blob
  # that claims healthy numbers alongside this marker is contradicting
  # itself, and the marker is the one sccache actually meant.
  if grep -qiE 'sccache: error:|server startup failed|cache storage failed to read' <<<"$stats"; then
    echo "cache-env.sh: sccache reported a startup failure -- treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # Extract the value of an exact stats field, e.g. "Cache hits" -- anchored
  # to the whole line so it can't also match "Cache hits rate" or "Cache
  # hits (C/C++)", which real sccache prints on neighbouring lines sharing
  # the same prefix.
  field() {
    grep -E "^${1}[[:space:]]+[0-9]+[[:space:]]*\$" <<<"$stats" | head -n1 | tr -dc '0-9'
  }

  requests=$(field "Compile requests")
  hits=$(field "Cache hits")
  errors=$(field "Cache errors")
  read_errors=$(field "Cache read errors")
  write_errors=$(field "Cache write errors")
  timeouts=$(field "Cache timeouts")

  # Real sccache always prints all six of these fields. A blob missing one
  # is not real sccache output, and guessing that the missing field would
  # have been zero is exactly the failure mode this file exists to prevent.
  if [ -z "$requests" ] || [ -z "$hits" ] || [ -z "$errors" ] \
     || [ -z "$read_errors" ] || [ -z "$write_errors" ] || [ -z "$timeouts" ]; then
    echo "cache-env.sh: cache stats missing expected fields -- cannot tell, treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # Partial failures that DID move a counter.
  if [ "$errors" -gt 0 ] || [ "$read_errors" -gt 0 ] || [ "$write_errors" -gt 0 ] || [ "$timeouts" -gt 0 ]; then
    echo "cache-env.sh: sccache reported cache errors (errors=$errors read=$read_errors write=$write_errors timeouts=$timeouts) -- treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # Zero compile requests, with an otherwise clean bill of health, is the
  # dead-backend fingerprint: the server never got a single request through,
  # which reads identically to "never asked" unless this is checked -- so it
  # does not get to default to COLD.
  if [ "$requests" -eq 0 ]; then
    echo "cache-env.sh: 0 compile requests recorded -- the cache never came up, treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # Compiles happened and the backend answered. No hits yet is a normal,
  # healthy cold cache -- NOT the same finding as any branch above.
  if [ "$hits" -eq 0 ]; then echo "COLD"; exit 0; fi
  echo "WARM"; exit 0
fi

BUCKET="${1:?usage: cache-env.sh <bucket> | --verdict <stats>}"
: "${S3_ENDPOINT:?S3_ENDPOINT must be set}"

# A bucket name becomes a single KEY=VALUE line below; a stray newline in it
# would inject an extra line into whatever reads this script's output next.
case "$BUCKET" in
  *$'\n'*)
    echo "cache-env.sh: bucket name must not contain a newline" >&2
    exit 1
    ;;
esac

# Strip scheme and port: sccache wants a bare host.
HOST="${S3_ENDPOINT#*://}"; HOST="${HOST%%:*}"

# Credentials are supplied to the process through the environment by the caller
# and are deliberately NOT printed here.
echo "RUSTC_WRAPPER=sccache"
echo "SCCACHE_BUCKET=${BUCKET}"
echo "SCCACHE_ENDPOINT=${HOST}"
echo "SCCACHE_S3_USE_SSL=true"
echo "SCCACHE_S3_NO_CREDENTIALS=0"
