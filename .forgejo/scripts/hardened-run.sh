#!/usr/bin/env bash
# Run a command inside a container whose CPU and memory caps are VERIFIED, not
# merely requested. Reusable: nothing in here names a project.
#
# Why the verification exists: upstream's CI sets no caps at all, because
# GitHub gives every job a disposable VM. Our runner shares a cluster node.
# On 2026-09-15 an uncapped Rust build cost the control plane its leader
# leases -- 30.2 s etcd applies, 408 apiserver timeouts in a minute, seven
# controllers exited. A cap that is passed but not checked would have looked
# identical to one that worked.
set -uo pipefail

CPUS="" MEM="" LABEL="hardened"
while [ $# -gt 0 ]; do
  case "$1" in
    --cpus)   CPUS="$2"; shift 2 ;;
    --memory) MEM="$2";  shift 2 ;;
    --label)  LABEL="$2"; shift 2 ;;
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

if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then
  echo "would run: docker run ${ARGS[*]} -- $*"
fi

# Assert the cap actually took. In a dry run the value is injected by the test;
# in a real run it is read back from the runtime.
if [ -n "${HARDENED_RUN_FAKE_INSPECT:-}" ]; then
  ACTUAL="$HARDENED_RUN_FAKE_INSPECT"
elif [ "${HARDENED_RUN_DRY:-}" = "1" ]; then
  ACTUAL=""
else
  docker run -d "${ARGS[@]}" --entrypoint sleep "${HARDENED_RUN_IMAGE:?set HARDENED_RUN_IMAGE}" 86400 >/dev/null || {
    echo "hardened-run: could not start the capped container" >&2; exit 91; }
  ACTUAL="$(docker inspect -f '{{.HostConfig.Memory}}' "$NAME" 2>/dev/null)"
fi

if [ -n "$ACTUAL" ] && [ "$ACTUAL" = "0" ]; then
  echo "hardened-run: FATAL -- the runtime reports a memory cap of 0, so no cap
took effect. Refusing to run an uncapped build on a shared node." >&2
  [ "${HARDENED_RUN_DRY:-}" = "1" ] || docker rm -f "$NAME" >/dev/null 2>&1
  exit 90
fi

if [ "${HARDENED_RUN_DRY:-}" = "1" ]; then exit 0; fi

trap 'docker rm -f "$NAME" >/dev/null 2>&1' EXIT
docker exec "$NAME" "$@"
