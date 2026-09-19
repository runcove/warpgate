#!/usr/bin/env bash
# A stub `hardened-run.sh` that RUNS what it was handed, instead of only
# recording it (that is hardened-run-stub.sh's job).
#
# It exists for one thing the other stub cannot prove: run-check.sh now
# prefixes a tools probe to the command it gives the sandbox, and a probe that
# is merely COMPOSED correctly is not a probe that refuses correctly. This
# executes the exact string, so the probe's own shell runs and its exit status
# is observed rather than assumed.
#
# No container runtime is involved and none is simulated: the commands in
# checks-tools-test.yaml are `echo`s, so nothing this stub runs can be
# expensive. That is deliberate. Pointing a test like this at the REAL
# checks.yaml would hand it `just clippy` and start a Rust build on the machine
# running the tests -- which happened on 2026-09-19 while developing this, and
# was harmless only because `cargo cranky` was not installed.
set -uo pipefail
while [ $# -gt 0 ]; do
  if [ "$1" = "--" ]; then shift; break; fi
  shift
done
[ $# -gt 0 ] || { echo "hardened-run-exec-stub: no command after --" >&2; exit 2; }
exec "$@"
