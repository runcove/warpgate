#!/usr/bin/env bash
# A stub `hardened-run.sh` for testing run-check.sh's OWN invocation of it --
# specifically, which --forward-env flags run-check.sh actually passes on
# the capped path. No container runtime involved; this only ever replaces
# hardened-run.sh itself (via a symlink at the test's temp dir), never the
# real one.
#
# Recognised env vars:
#   STUB_HARDENED_RUN_ARGS_FILE  if set, the full argument list this stub was
#                                 called with (one per line) is written there.
#   STUB_HARDENED_RUN_RC         exit code to return (default 0)
set -uo pipefail

if [ -n "${STUB_HARDENED_RUN_ARGS_FILE:-}" ]; then
  printf '%s\n' "$@" > "$STUB_HARDENED_RUN_ARGS_FILE"
fi
exit "${STUB_HARDENED_RUN_RC:-0}"
