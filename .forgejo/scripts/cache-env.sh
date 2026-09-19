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
#
# Exit 93 ("required configuration missing") joins the same reserved refusal
# band hardened-run.sh documents (89-99) and run-check.sh checks for as a
# whole -- bucket mode uses only this one code from it; --verdict's own
# COLD/WARM/FAILED vocabulary and exit 0/1 are unrelated and unaffected.
set -uo pipefail

if [ "${1:-}" = "--verdict" ]; then
  stats="${2:-}"

  # Nothing to read at all. Deliberately redundant with the missing-fields
  # guard below -- an empty string also fails every `field` match, so that
  # guard alone would already catch this case. This early exit exists only
  # for a clearer message ("no stats given" vs "missing expected fields");
  # the missing-fields guard is the one actually load-bearing here. Do not
  # delete either on the assumption the other one covers it by accident --
  # delete this one and the message gets vaguer, delete that one and the
  # script breaks.
  if [ -z "$stats" ]; then
    echo "cache-env.sh: no cache stats given -- cannot tell, treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # sccache's own account of its startup outranks every counter below: a blob
  # that claims healthy numbers alongside this marker is contradicting
  # itself, and the marker is the one sccache actually meant.
  #
  # This is NOT corroborated once compile requests are above zero, and must
  # not be treated as if it were. It catches exactly one shape: the server
  # crashing before it ever took a request, which is also the shape the
  # requests==0 fingerprint below catches on its own -- reworded or
  # localised, this string stops matching and that fingerprint is then the
  # only thing standing between a dead-at-startup backend and a false COLD.
  # It says nothing at all about a backend that answered at startup and
  # degraded or stopped retaining afterwards (compiles keep running, no
  # error text, no error counter): that failure is invisible to a single
  # stats read by construction, not by a gap in this pattern, and is a named
  # Task 9 follow-up (run-to-run evidence, not a better parse). Do not
  # "simplify" this check and the requests==0 check into one: they cover
  # different shapes and only overlap in the one case both were built for.
  if grep -qiE 'sccache: error:|server startup failed|cache storage failed to read' <<<"$stats"; then
    echo "cache-env.sh: sccache reported a startup failure -- treating as FAILED" >&2
    echo "FAILED"; exit 1
  fi

  # Extract the value of an exact stats field, e.g. "Cache hits" -- anchored
  # to the whole line so it can't also match "Cache hits rate" or "Cache
  # hits (C/C++)", which real sccache prints on neighbouring lines sharing
  # the same prefix. `[0-9]+` deliberately accepts digits only: a value that
  # isn't a plain integer (blank, "-", garbled) fails this match and falls
  # through to the missing-fields guard below as unreadable, which is the
  # correct outcome. Do not loosen this to be "helpful" to odd input --
  # that is exactly the guessing this file exists to refuse.
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

# Not `"${1:?...}"`/`": ${S3_ENDPOINT:?...}"` -- either form kills the script
# via bash's own parameter-expansion error, exit 1, which is indistinguishable
# from an ordinary failure. Missing required configuration is a refusal like
# hardened-run.sh's and run-check.sh's, so it gets the same code: 93.
#
# THIS EXIT STATUS IS LOAD-BEARING. This script's only output in bucket mode
# is a run of `KEY=VALUE` lines meant to be captured and `eval`'d by a
# caller. `eval "$(cache-env.sh <bucket>)"` of a refusal that printed
# nothing is `eval` of an empty string, which succeeds (exit 0) regardless
# of why this script refused. A caller that does not check `$?` before
# evaluating gets a build that silently runs with no compiler cache at
# all -- correct, just an hour slower, and nothing reports why. Check the
# exit status before evaluating the output; do not assume a non-empty
# capture just because the command "ran".
if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "cache-env.sh: FATAL -- usage: cache-env.sh <bucket> | --verdict <stats> (required argument missing). Refusing to run." >&2
  exit 93
fi
BUCKET="$1"

if [ -z "${S3_ENDPOINT:-}" ]; then
  echo "cache-env.sh: FATAL -- S3_ENDPOINT must be set. Refusing to run." >&2
  exit 93
fi

# A bucket name becomes a single KEY=VALUE line below; a stray newline in it
# would inject an extra line into whatever reads this script's output next.
case "$BUCKET" in
  *$'\n'*)
    echo "cache-env.sh: bucket name must not contain a newline" >&2
    exit 1
    ;;
esac

# Strip the scheme and any trailing path, and KEEP THE PORT.
#
# This line used to also strip the port, on the stated premise that "sccache
# wants a bare host". That premise is false, and it would have cost a CI run to
# learn. sccache 0.17.0's own S3 docs — the version this image installs —
# document the variable as:
#
#     SCCACHE_ENDPOINT=<ip>:<port>   ... such as MinIO or DigitalOcean storage
#
# and our endpoint is QuObjects on a NON-default port. Measured 2026-09-19:
# oga2.tenfourty.site:8010 is OPEN and :443 is CLOSED, so a bare host sends
# sccache to a closed port. The failure that produces is a connection error
# arriving immediately after the credentials are installed, which is read as a
# credentials problem by everyone who looks at it.
#
# The scheme still goes, because sccache takes the protocol from
# SCCACHE_S3_USE_SSL (emitted below) rather than from the endpoint string; a
# trailing path goes too, since the endpoint is a host, not a URL to an object.
HOST="${S3_ENDPOINT#*://}"; HOST="${HOST%%/*}"

# Credentials are supplied to the process through the environment by the caller
# and are deliberately NOT printed here.
echo "RUSTC_WRAPPER=sccache"
echo "SCCACHE_BUCKET=${BUCKET}"
echo "SCCACHE_ENDPOINT=${HOST}"
# REQUIRED, not optional, and its absence cost run 573. sccache v0.17.0's
# docs/S3.md lists exactly two required variables for this backend --
# SCCACHE_BUCKET and SCCACHE_REGION -- and without the region sccache refuses
# to start at all:
#
#   sccache: error: Server startup failed: create s3 cache failed:
#   ConfigInvalid (permanent) at Builder::build, context: { service: s3 }
#   => region is missing. Please find it by S3::detect_region() or set them in env.
#
# `auto` is the documented value for a custom endpoint ("can be set to `auto`
# if using a custom endpoint"), which is what QuObjects is. It is NOT a guess
# at a plausible AWS region name: region detection is meaningless against a
# non-AWS store, and `auto` is how the docs say to tell sccache so.
#
# The lesson this line records is not "we forgot a variable". Both cache bugs
# in this file came from checking what ONE variable wanted and never asking
# what else was mandatory -- first SCCACHE_ENDPOINT's host:port form, then
# this. When adding a backend variable, read the backend's REQUIRED list, not
# just the entry for the value you happen to be holding.
echo "SCCACHE_REGION=auto"
echo "SCCACHE_S3_USE_SSL=true"
echo "SCCACHE_S3_NO_CREDENTIALS=0"
