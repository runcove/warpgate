#!/usr/bin/env bash
# Run a command inside a container whose CPU and memory caps are VERIFIED, not
# merely requested. Reusable: nothing in here names a project.
#
# Why the verification exists: upstream's CI sets no caps at all, because
# GitHub gives every job a disposable VM. Our runner shares a cluster node --
# an in-cluster dind sidecar -- whose own memory limit does not bound what it
# launches: containers it creates land in a sibling cgroup at the host root.
# So the per-`docker run` cap this script sets, and then reads back to
# confirm, is the only bound that exists. On 2026-09-15 an uncapped Rust
# build cost the control plane its leader leases -- 30.2 s etcd applies,
# 408 apiserver timeouts in a minute, seven controllers exited. A cap that is
# passed but not checked would have looked identical to one that worked --
# and a check that can be fooled by a failed or empty read-back is no better
# (fix round 1: a stub whose `docker inspect` exited 1 let the command run
# with no cap at all, silently, because the old check only ever compared the
# read-back against the literal string "0").
#
# Exit codes 89-99 are this script's reserved "could not run safely" band --
# not a statement about whatever command was asked to run. Every caller
# (run-check.sh, and anything else that wraps this script) must treat the
# whole band as a refusal, not just the specific codes documented here:
# enumerating known codes is how a new one gets misread as an ordinary
# result. Documented codes so far: 90 cap read-back failed or didn't match,
# 91 the container could not be created, 92 a test hook leaked into a real
# CI run, 93 required configuration is missing (e.g. HARDENED_RUN_IMAGE
# unset).
set -uo pipefail

# The test hooks below exist so this script's failure paths are testable on a
# host with no container runtime. If any of them leak into a real CI run --
# via a copied env: block or a prior step's GITHUB_ENV -- they silently
# defeat every guard in this file, so fail loudly instead of running as a
# quiet no-op.
for var in HARDENED_RUN_DRY HARDENED_RUN_FAKE_INSPECT HARDENED_RUN_FAKE_INSPECT_CPUS; do
  val="${!var:-}"
  if [ -n "$val" ] && { [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${FORGEJO_ACTIONS:-}" ]; }; then
    echo "hardened-run: FATAL -- $var is set while CI/GITHUB_ACTIONS/FORGEJO_ACTIONS is present.
This variable exists only to test this script without a container runtime; left set inside real
CI it would silently defeat the cap assertion. Refusing to run." >&2
    exit 92
  fi
done

CPUS="" MEM="" LABEL="hardened"
FORWARD_VARS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --cpus)   CPUS="$2"; shift 2 ;;
    --memory) MEM="$2";  shift 2 ;;
    --label)  LABEL="$2"; shift 2 ;;
    # The caller names a VARIABLE, never a value -- so no secret is ever a
    # command-line argument, and none shows up in a `set -x` trace or a
    # process listing. This script still names no project (the caller
    # decides what crosses the boundary); repeatable so a caller can forward
    # as many names as it needs.
    --forward-env) FORWARD_VARS+=("$2"); shift 2 ;;
    --) shift; break ;;
    *) echo "hardened-run: unknown argument $1" >&2; exit 2 ;;
  esac
done

[ -n "$CPUS" ] || { echo "hardened-run: --cpus is required" >&2; exit 2; }
[ -n "$MEM" ]  || { echo "hardened-run: --memory is required. Running without a
memory cap is the failure mode this script exists to prevent." >&2; exit 2; }
[ $# -gt 0 ]   || { echo "hardened-run: no command given" >&2; exit 2; }

NAME="${LABEL}-${GITHUB_RUN_ID:-local}-$$"

# --memory-swap must equal --memory. If it is left unset the container may swap
# instead of being killed, so the limit bounds nothing.
ARGS=(--rm --name "$NAME"
      "--cpus=${CPUS}"
      "--memory=${MEM}" "--memory-swap=${MEM}")

# Only a variable that is actually SET, with a non-empty value, in this
# script's own environment gets forwarded. `-e VAR` (name-only) tells docker
# to copy the value from here -- for a variable that is unset OR set to "",
# that copies an empty string into the container, which is worse than the
# variable being absent there too: sccache would start, try to authenticate
# with an empty credential, and fail in a way that looks like a
# configuration problem rather than the absent-cache problem it actually is.
# Reported by name and count below -- never by value, and never omitted:
# a silent forward is exactly as untestable as the gap this flag exists to
# close.
FORWARD_ARGS=()
FORWARDED_NAMES=()
for v in "${FORWARD_VARS[@]}"; do
  if [ -n "${!v:-}" ]; then
    FORWARD_ARGS+=(-e "$v")
    FORWARDED_NAMES+=("$v")
  fi
done
echo "hardened-run: forwarded ${#FORWARDED_NAMES[@]} variable(s) into the capped container: ${FORWARDED_NAMES[*]:-(none)}"

if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then
  echo "would run: docker run ${ARGS[*]} ${FORWARD_ARGS[*]} -- $*"
fi

# Convert what we asked for into the units the runtime reports back (bytes
# for memory, nanocpus for cpus), so the assertion below can compare like
# with like instead of guessing what "failed to apply" happens to look like.
mem_to_bytes() {
  local v="$1" num unit mult
  [[ "$v" =~ ^([0-9]+(\.[0-9]+)?)([a-zA-Z]*)$ ]] || return 1
  num="${BASH_REMATCH[1]}"; unit="${BASH_REMATCH[3],,}"
  case "$unit" in
    ""|b) mult=1 ;;
    k) mult=1024 ;;
    m) mult=$((1024*1024)) ;;
    g) mult=$((1024*1024*1024)) ;;
    *) return 1 ;;
  esac
  LC_ALL=C awk -v n="$num" -v m="$mult" 'BEGIN{printf "%.0f", n*m}'
}

cpus_to_nanocpus() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+(\.[0-9]+)?$ ]] || return 1
  LC_ALL=C awk -v c="$v" 'BEGIN{printf "%.0f", c*1000000000}'
}

EXPECT_MEM="$(mem_to_bytes "$MEM")" \
  || { echo "hardened-run: cannot parse --memory value '$MEM'" >&2; exit 2; }
EXPECT_CPUS="$(cpus_to_nanocpus "$CPUS")" \
  || { echo "hardened-run: cannot parse --cpus value '$CPUS'" >&2; exit 2; }

# Assert a single cap actually took, by reading it back and comparing to what
# we asked for -- not by pattern-matching what "it failed" happens to look
# like. All four conditions must hold: the read-back must have succeeded,
# produced something, produced a number, and that number must equal what was
# requested. Any failure refuses rather than runs, and says which condition
# failed plus expected vs actual.
assert_cap() {
  local label="$1" expect="$2" rc="$3" actual="$4"
  if [ "$rc" -ne 0 ]; then
    echo "hardened-run: FATAL -- could not read back the $label (docker inspect exited $rc);
expected $expect. An unreadable cap is indistinguishable from one that never took effect --
refusing to run." >&2
    return 1
  fi
  if [ -z "$actual" ]; then
    echo "hardened-run: FATAL -- docker inspect returned no $label value (expected $expect).
Refusing to run." >&2
    return 1
  fi
  if ! [[ "$actual" =~ ^[0-9]+$ ]]; then
    echo "hardened-run: FATAL -- docker inspect returned a non-numeric $label value '$actual'
(expected $expect). Refusing to run." >&2
    return 1
  fi
  # A read-back of 0 always means "no cap took effect", in docker's own
  # semantics, regardless of what was requested -- checked unconditionally
  # so this can never be satisfied by asking for 0 and getting 0 back.
  if [ "$actual" = "0" ]; then
    echo "hardened-run: FATAL -- the runtime reports the $label at 0, meaning no cap took effect
(expected $expect). Refusing to run an uncapped build regardless of what was requested." >&2
    return 1
  fi
  if [ "$actual" != "$expect" ]; then
    echo "hardened-run: FATAL -- $label did not take effect as requested (expected $expect,
runtime reports $actual). Refusing to run an incorrectly capped build." >&2
    return 1
  fi
  return 0
}

# In a dry run the read-back is whatever the test injects (per-property, via
# HARDENED_RUN_FAKE_INSPECT for memory and HARDENED_RUN_FAKE_INSPECT_CPUS for
# cpus); a property with no injected value is not checked at all, so a pure
# dry preview with neither set stays a no-op. Outside a dry run, both are
# always read back for real -- there is no way to check only one.
MEM_RC="" MEM_ACTUAL="" CPUS_RC="" CPUS_ACTUAL=""
HAVE_MEM=0 HAVE_CPUS=0
if [ -n "${HARDENED_RUN_FAKE_INSPECT:-}" ]; then
  MEM_RC=0; MEM_ACTUAL="$HARDENED_RUN_FAKE_INSPECT"; HAVE_MEM=1
fi
if [ -n "${HARDENED_RUN_FAKE_INSPECT_CPUS:-}" ]; then
  CPUS_RC=0; CPUS_ACTUAL="$HARDENED_RUN_FAKE_INSPECT_CPUS"; HAVE_CPUS=1
fi

if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then
  : # nothing further to read back; whatever was injected above is all there is
elif [ "$HAVE_MEM" -eq 0 ] || [ "$HAVE_CPUS" -eq 0 ]; then
  # Not `"${HARDENED_RUN_IMAGE:?set HARDENED_RUN_IMAGE}"` -- that form kills the
  # script via bash's own parameter-expansion error, exit 1, before `docker run`
  # is ever reached, which is indistinguishable from an ordinary script failure
  # and outside this file's own exit-code contract. A missing required setting is
  # a refusal like the ones above it, not a bare crash, so it gets its own code
  # in the same reserved band: 93, "required configuration missing".
  [ -n "${HARDENED_RUN_IMAGE:-}" ] || {
    echo "hardened-run: FATAL -- HARDENED_RUN_IMAGE is not set. Refusing to run." >&2
    exit 93
  }
  docker run -d "${ARGS[@]}" "${FORWARD_ARGS[@]}" --entrypoint sleep "$HARDENED_RUN_IMAGE" 86400 >/dev/null || {
    echo "hardened-run: could not start the capped container" >&2; exit 91; }
  if [ "$HAVE_MEM" -eq 0 ]; then
    MEM_ACTUAL="$(docker inspect -f '{{.HostConfig.Memory}}' "$NAME" 2>/dev/null)"; MEM_RC=$?
    HAVE_MEM=1
  fi
  if [ "$HAVE_CPUS" -eq 0 ]; then
    CPUS_ACTUAL="$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$NAME" 2>/dev/null)"; CPUS_RC=$?
    HAVE_CPUS=1
  fi
fi

FAILED=0
[ "$HAVE_MEM" -eq 1 ]  && { assert_cap "memory cap" "$EXPECT_MEM"  "$MEM_RC"  "$MEM_ACTUAL"  || FAILED=1; }
[ "$HAVE_CPUS" -eq 1 ] && { assert_cap "cpu cap"    "$EXPECT_CPUS" "$CPUS_RC" "$CPUS_ACTUAL" || FAILED=1; }

if [ "$FAILED" -eq 1 ]; then
  [ "${HARDENED_RUN_DRY:-}" = "1" ] || docker rm -f "$NAME" >/dev/null 2>&1
  exit 90
fi

if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then exit 0; fi

trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
docker exec "${FORWARD_ARGS[@]}" "$NAME" "$@"
