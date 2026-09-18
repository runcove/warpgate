#!/usr/bin/env bash
# sccache configuration, and the verdict that tells a cold cache from a broken one.
#
# Upstream caches with GitHub services (Swatinem/rust-cache, type=gha) which do
# not exist on our forge, so none of it is inheritable. This is an addition to
# upstream's approach, not an adoption of it.
set -uo pipefail

if [ "${1:-}" = "--verdict" ]; then
  stats="${2:-}"
  errors=$(grep -i "Cache errors" <<<"$stats" | tr -dc '0-9')
  hits=$(grep -i "Cache hits"   <<<"$stats" | tr -dc '0-9')
  misses=$(grep -i "Cache misses" <<<"$stats" | tr -dc '0-9')
  errors="${errors:-0}"; hits="${hits:-0}"; misses="${misses:-0}"
  if [ "$errors" -gt 0 ]; then
    echo "FAILED"; exit 1
  fi
  # Cold: the cache answered, and had nothing for us. Normal on a new bucket or
  # after a toolchain bump. NOT a failure -- and not the same as FAILED, which is
  # why these are two branches and not one.
  if [ "$hits" -eq 0 ] && [ "$misses" -eq 0 ]; then echo "COLD"; exit 0; fi
  echo "WARM"; exit 0
fi

BUCKET="${1:?usage: cache-env.sh <bucket> | --verdict <stats>}"
: "${S3_ENDPOINT:?S3_ENDPOINT must be set}"

# Strip scheme and port: sccache wants a bare host.
HOST="${S3_ENDPOINT#*://}"; HOST="${HOST%%:*}"

# Credentials are supplied to the process through the environment by the caller
# and are deliberately NOT printed here.
echo "RUSTC_WRAPPER=sccache"
echo "SCCACHE_BUCKET=${BUCKET}"
echo "SCCACHE_ENDPOINT=${HOST}"
echo "SCCACHE_S3_USE_SSL=true"
echo "SCCACHE_S3_NO_CREDENTIALS=0"
