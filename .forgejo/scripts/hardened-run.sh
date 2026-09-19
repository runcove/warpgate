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
# result. This script's own codes are 90 (cap read-back failed or didn't
# match), 91 (the container could not be created), 92/93 (below) and 98 (the
# source could not be delivered into the container, below). The full,
# current registry of every code in the band -- including the ones other
# scripts have added since -- is EXIT_CODES.md; that is the one to check
# before allocating a new one, not this comment.
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

CPUS="" MEM="" LABEL="hardened" SOURCE="" WORKDIR="" VERIFY_FILE=""
FORWARD_VARS=()
ADD_HOSTS=()
DNS_SERVERS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --cpus)    CPUS="$2"; shift 2 ;;
    --memory)  MEM="$2";  shift 2 ;;
    --label)   LABEL="$2"; shift 2 ;;
    # Both optional, and independent of --cpus/--memory: this script is
    # reusable by any caller, including one that wants a bare capped
    # container with nothing copied into it, so a caller that passes
    # neither gets exactly today's behaviour. A caller that passes one
    # without the other has made a mistake, not a choice -- caught below,
    # once parsing has seen everything.
    --source)      SOURCE="$2"; shift 2 ;;
    --workdir)     WORKDIR="$2"; shift 2 ;;
    # Relative to --workdir. Optional even when --source is given: this
    # script names no project (see the file header), so it has no business
    # hardcoding a project's manifest filename -- that knowledge belongs to
    # the caller (run-check.sh passes --verify-file Cargo.toml, because it
    # already knows this is a cargo workspace). Without it, delivery is
    # still verified, just more weakly -- see the source-delivery block
    # below for what that means.
    --verify-file) VERIFY_FILE="$2"; shift 2 ;;
    # The caller names a VARIABLE, never a value -- so no secret is ever a
    # command-line argument, and none shows up in a `set -x` trace or a
    # process listing. This script still names no project (the caller
    # decides what crosses the boundary); repeatable so a caller can forward
    # as many names as it needs.
    --forward-env) FORWARD_VARS+=("$2"); shift 2 ;;
    # A NAME:ADDRESS mapping placed in the container's /etc/hosts. Pure
    # passthrough: this script does no name resolution of its own and knows
    # nothing about which host matters or why. That is the caller's knowledge,
    # exactly as with --verify-file, and for the same reason -- a caller that
    # decides a lookup failure is survivable (run-check.sh, for the build
    # cache) must not have that decision taken for it in here.
    #
    # Why a caller needs this at all, measured in run 604: the inner dind
    # daemon inherits the job container's loopback resolver (127.0.0.11),
    # treats it as unusable, and falls back to Docker's built-in defaults --
    # Google's public servers -- which cannot resolve a homelab name. A
    # container it creates therefore cannot reach anything on the LAN by name,
    # while the job container resolves the same name without trouble.
    # Repeatable.
    --add-host)    ADD_HOSTS+=("$2"); shift 2 ;;
    # --dns is the general form of the same fault --add-host works around one
    # name at a time. Run 608 measured that a container the inner daemon
    # starts on its DEFAULT bridge does honour --dns (`# Overrides:
    # [nameservers]`), and that the cluster resolver is reachable from there:
    # a cluster name and a homelab name both came back rc=0, where the same
    # container without the flag got Google and rc=2. This script does not
    # decide WHICH resolver -- it takes one and passes it through, exactly as
    # it takes --add-host without knowing which host matters. Repeatable.
    --dns)         DNS_SERVERS+=("$2"); shift 2 ;;
    --) shift; break ;;
    *) echo "hardened-run: unknown argument $1" >&2; exit 2 ;;
  esac
done

[ -n "$CPUS" ] || { echo "hardened-run: --cpus is required" >&2; exit 2; }
[ -n "$MEM" ]  || { echo "hardened-run: --memory is required. Running without a
memory cap is the failure mode this script exists to prevent." >&2; exit 2; }
[ $# -gt 0 ]   || { echo "hardened-run: no command given" >&2; exit 2; }
# Both --workdir and --verify-file require --source -- checked together, in
# one message naming EVERY flag that actually triggered it, not just
# whichever happened to be checked first. `--workdir X --verify-file Y` with
# no --source used to print only "--source is required when --workdir is
# given" and never mention --verify-file at all, even though --verify-file
# was equally the reason this refused -- silently dropping half of a
# two-flag mistake from the one message a caller gets to read.
NEEDS_SOURCE=()
[ -n "$WORKDIR" ]     && NEEDS_SOURCE+=("--workdir")
[ -n "$VERIFY_FILE" ] && NEEDS_SOURCE+=("--verify-file")
if [ -z "$SOURCE" ] && [ "${#NEEDS_SOURCE[@]}" -gt 0 ]; then
  echo "hardened-run: --source is required when ${NEEDS_SOURCE[*]} is given" >&2
  exit 2
fi
if [ -n "$SOURCE" ] && [ -z "$WORKDIR" ]; then
  echo "hardened-run: --workdir is required when --source is given" >&2
  exit 2
fi

# A malformed mapping is a usage error, not something to pass to docker and
# let it complain in its own words halfway through a run. Refused at parse
# time, like --source without --workdir, and the message names the value that
# was wrong rather than saying one of them was: a caller passing several gets
# told which.
for m in ${ADD_HOSTS[@]+"${ADD_HOSTS[@]}"}; do
  case "$m" in
    *:*) : ;;
    *) echo "hardened-run: --add-host '$m' is not NAME:ADDRESS" >&2; exit 2 ;;
  esac
  [ -n "${m%%:*}" ] || { echo "hardened-run: --add-host '$m' has an empty name" >&2; exit 2; }
  [ -n "${m##*:}" ] || { echo "hardened-run: --add-host '$m' has an empty address" >&2; exit 2; }
done

# A resolver has to be a literal ADDRESS. A hostname here would have to be
# resolved to be used, by the very resolver it is trying to configure, and
# docker would accept it and produce a container whose DNS silently does
# nothing. Refused at parse time with the value named, like --add-host above.
# The shape is checked here; WHICH address is a policy question and belongs to
# the caller (run-check.sh), which is the only side that knows what a
# plausible resolver is for this environment.
for d in ${DNS_SERVERS[@]+"${DNS_SERVERS[@]}"}; do
  case "$d" in
    *[!0-9.]*|"") echo "hardened-run: --dns '$d' is not an IPv4 address" >&2; exit 2 ;;
  esac
  __oc=0
  __rest="$d"
  while [ -n "$__rest" ]; do
    __part="${__rest%%.*}"
    [ -n "$__part" ] || { echo "hardened-run: --dns '$d' is not an IPv4 address" >&2; exit 2; }
    [ "$__part" -le 255 ] 2>/dev/null || { echo "hardened-run: --dns '$d' has an octet above 255" >&2; exit 2; }
    __oc=$((__oc+1))
    case "$__rest" in *.*) __rest="${__rest#*.}" ;; *) __rest="" ;; esac
  done
  [ "$__oc" -eq 4 ] || { echo "hardened-run: --dns '$d' does not have four octets" >&2; exit 2; }
done

NAME="${LABEL}-${GITHUB_RUN_ID:-local}-$$"

# --memory-swap must equal --memory. If it is left unset the container may swap
# instead of being killed, so the limit bounds nothing.
ARGS=(--rm --name "$NAME"
      "--cpus=${CPUS}"
      "--memory=${MEM}" "--memory-swap=${MEM}")
for m in ${ADD_HOSTS[@]+"${ADD_HOSTS[@]}"}; do ARGS+=(--add-host "$m"); done
for d in ${DNS_SERVERS[@]+"${DNS_SERVERS[@]}"}; do ARGS+=(--dns "$d"); done

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

# Deliver the source tree, when the caller asked for one (run-check.sh does,
# for every capped check). `docker cp` is the established mechanism on this
# platform -- the forge's own runner uses it to place files in job
# containers -- and, critically, is not a bind mount: this runner is
# docker-in-docker, so a `-v "$PWD:/work"` would have the DAEMON resolve the
# path against its own filesystem and silently mount an empty or unrelated
# directory, and every check would then fail exactly as though the code
# under test were broken, with nothing in the output to tell the two apart.
# `docker cp SRC/. DEST` (trailing `/.`) copies SRC's contents; `docker cp
# SRC DEST` copies SRC itself, nesting everything one level deeper -- get
# this wrong and every relative path inside the container misses. This
# copies the working directory as it stands, not `git archive HEAD`: an
# archive would be tidier (no .git, no target/) but would silently drop
# anything a previous CI step generated into the tree, and at least one
# check (`just openapi-all`) may depend on generated files.
if [ -n "$SOURCE" ]; then
  docker exec "$NAME" mkdir -p "$WORKDIR" || {
    echo "hardened-run: FATAL -- could not create $WORKDIR inside the container
(docker exec mkdir failed). Refusing to run with no source delivered." >&2
    exit 98
  }
  if ! docker cp "$SOURCE/." "$NAME:$WORKDIR"; then
    echo "hardened-run: FATAL -- docker cp itself failed copying $SOURCE into
$NAME:$WORKDIR. Refusing to run with no source delivered." >&2
    exit 98
  fi
  # The cheap positive assertion that is the whole difference between "your
  # code is broken" and "your code is not there": checked separately from
  # docker cp's own exit status above, because relying on the exit status
  # alone would make a `docker cp` that reports success having copied the
  # wrong thing indistinguishable from a workdir that doesn't exist -- both
  # would otherwise reach the check silently.
  #
  # Strongest when the caller names a file it actually expects
  # (--verify-file, relative to --workdir): a wrong-directory copy is still
  # caught, because the named file only exists in the right one. Without
  # --verify-file the check is deliberately weaker -- only "the workdir is
  # non-empty" -- and says so out loud, because a wrong-directory copy that
  # happens to land somewhere non-empty would sail straight through it; a
  # caller that can name a file should.
  if [ -n "$VERIFY_FILE" ]; then
    if ! docker exec "$NAME" test -f "$WORKDIR/$VERIFY_FILE"; then
      echo "hardened-run: FATAL -- docker cp exited 0 but $WORKDIR/$VERIFY_FILE is not
present inside the container afterwards -- the copy landed in the wrong place, or
copied the wrong thing. Refusing to run against a container with no verified
source." >&2
      exit 98
    fi
    echo "hardened-run: verified source present at $NAME:$WORKDIR/$VERIFY_FILE"
  else
    echo "hardened-run: no --verify-file given -- only checking that $WORKDIR is
non-empty, which a wrong-directory copy could also satisfy. Pass --verify-file for a
stronger check." >&2
    LISTING=$(docker exec "$NAME" find "$WORKDIR" -mindepth 1 -maxdepth 1 2>/dev/null)
    if [ -z "$LISTING" ]; then
      echo "hardened-run: FATAL -- docker cp exited 0 but $WORKDIR is empty inside the
container afterwards. Refusing to run against a container with no verified source." >&2
      exit 98
    fi
    echo "hardened-run: verified $NAME:$WORKDIR is non-empty (weaker check -- no
--verify-file was given)"
  fi
fi

EXEC_ARGS=("${FORWARD_ARGS[@]}")
[ -n "$SOURCE" ] && EXEC_ARGS+=(--workdir "$WORKDIR")
docker exec "${EXEC_ARGS[@]}" "$NAME" "$@"
EXEC_RC=$?

# PEAK MEMORY, read before the EXIT trap removes the container.
#
# Why this can work at all: the container is started DETACHED running `sleep
# 86400` and the check runs inside it via `docker exec`. So when a check is
# OOM-killed the container itself survives -- only the exec'd process dies --
# and its cgroup is still there to be read. A `docker run <cmd>` design would
# have destroyed the evidence at the moment it was created.
#
# Why unconditionally and not just on 137: a number is only diagnostic against a
# band, and the band comes from healthy runs. Printed only on failure, the first
# 137 would give one figure with nothing to compare it to -- which is the
# position runcove-ljvj.2 was filed from. A 137 alone cannot distinguish "needed
# 7.1 GB" from "needed 40 GB", and those argue for opposite decisions.
#
# NOTHING HERE MAY CHANGE THE CHECK'S RESULT. Every command is guarded and the
# script exits with EXEC_RC regardless. A diagnostic that can fail a build is a
# worse defect than the missing diagnostic it replaces.
peak_bytes=""
peak_src=""
peak_why=""
if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then
  peak_why="dry run"
else
  # cgroup v2 first (memory.peak), then v1 (memory.max_usage_in_bytes). Both are
  # kernel-maintained high-water marks, so a single read after the fact is the
  # true peak -- no sampling, nothing to miss between polls.
  for probe in "/sys/fs/cgroup/memory.peak" "/sys/fs/cgroup/memory/memory.max_usage_in_bytes"; do
    v=$(docker exec "$NAME" cat "$probe" 2>/dev/null | tr -dc '0-9') || v=""
    if [ -n "$v" ]; then peak_bytes="$v"; peak_src="${probe##*/}"; break; fi
  done
  [ -n "$peak_bytes" ] || peak_why="neither memory.peak (cgroup v2) nor memory.max_usage_in_bytes (v1) was readable"
fi

# THE PEAK SATURATES AT THE CAP, SO IT CANNOT ANSWER THE QUESTION ALONE.
# memory.current is held under memory.max by reclaim, so memory.peak can never
# exceed the cap by construction. Run 2836 showed what that costs: three of five
# capped checks read exactly "7168 MiB of 7168 MiB cap (100%)" -- unit-tests which
# PASSED, schema-compat which failed on its own merits, and release-build which was
# OOM-killed. Three different outcomes, one identical string. A peak at the ceiling
# says "it pressed against the limit" and can never say whether the check wanted
# 7.1 GiB or 40, which is the distinction runcove-ljvj.2 was filed to make because
# the two argue for opposite decisions (nudge the cap, or move the build).
#
# memory.events is the half that decides it. cgroup v2 maintains counters for THIS
# cgroup: `max` counts how many times allocation hit the limit, `oom` how many times
# it could not be reclaimed, and `oom_kill` how many processes the kernel killed
# INSIDE THIS CGROUP. That last one is the direct answer to "was it our cap or the
# host", which no exit code can give -- we have now watched one OOM arrive as 137
# and the same event arrive as 101 once sccache was in the way, because an exit code
# is a downstream report and oom_kill is the kernel's own count of what happened.
oom_kill=""
mem_max_events=""
oom_events=""
events_why=""
if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then
  events_why="dry run"
else
  ev=$(docker exec "$NAME" cat /sys/fs/cgroup/memory.events 2>/dev/null) || ev=""
  if [ -n "$ev" ]; then
    oom_kill=$(printf '%s\n' "$ev" | awk '$1=="oom_kill"{print $2; exit}')
    oom_events=$(printf '%s\n' "$ev" | awk '$1=="oom"{print $2; exit}')
    mem_max_events=$(printf '%s\n' "$ev" | awk '$1=="max"{print $2; exit}')
  else
    events_why="memory.events was not readable (cgroup v1 does not provide it)"
  fi
fi

if [ -n "$peak_bytes" ]; then
  peak_mib=$(( peak_bytes / 1048576 ))
  if [ -n "${EXPECT_MEM:-}" ] && [ "${EXPECT_MEM:-0}" -gt 0 ] 2>/dev/null; then
    cap_mib=$(( EXPECT_MEM / 1048576 ))
    pct=$(( peak_bytes * 100 / EXPECT_MEM ))
    echo "MEM-PEAK ${peak_mib} MiB of ${cap_mib} MiB cap (${pct}%), from ${peak_src}"
  else
    echo "MEM-PEAK ${peak_mib} MiB, from ${peak_src} (cap not parsed, so no percentage)"
  fi
else
  # Absence must never read as health. See trap 60 and this arc generally.
  echo "MEM-PEAK-UNAVAILABLE no peak-memory reading: ${peak_why:-unknown}. Exit was ${EXEC_RC}; if that is 137 the diagnosis this line exists for is NOT available."
fi

# The FLOOR caveat is keyed on oom_kill, NOT on an exit code. It used to fire only
# on 137, and run 2836 proved that wrong in the worst way: release-build's OOM came
# back as 101 because sccache caught the SIGKILL and reported it as an ordinary
# compile failure, so the one check that most needed this caveat was the only one
# that did not get it. oom_kill is the event; an exit code is a rumour about it.
if [ -n "$oom_kill" ]; then
  echo "MEM-EVENTS oom_kill=${oom_kill} oom=${oom_events:-?} limit-hits=${mem_max_events:-?} (cgroup v2 memory.events, this container only). Exit was ${EXEC_RC}."
  if [ "$oom_kill" -gt 0 ] 2>/dev/null; then
    echo "MEM-EVENTS THE KERNEL KILLED ${oom_kill} PROCESS(ES) IN THIS CGROUP: the cap did this, not the host. Any MEM-PEAK above is a FLOOR on what the check wanted, not the amount it needed to finish -- it stops at the cap by construction, so it cannot tell you how much more it would have used."
  elif [ "$EXEC_RC" -ne 0 ]; then
    echo "MEM-EVENTS no OOM kill in this cgroup, so exit ${EXEC_RC} is NOT this cap. If something was killed, it was killed by the host and this container was not the cgroup it was charged to."
  fi
else
  echo "MEM-EVENTS-UNAVAILABLE ${events_why:-unknown}. Without it, a MEM-PEAK at 100% of cap cannot be told apart from one that merely brushed the limit and recovered, and exit ${EXEC_RC} cannot be attributed to the cap or the host."
fi

exit "$EXEC_RC"
