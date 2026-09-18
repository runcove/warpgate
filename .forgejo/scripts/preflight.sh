#!/usr/bin/env bash
# Verify, before any check executes, that this job container can actually
# run one: python3 present, the Python 'yaml' module importable, the docker
# CLI present, and the docker daemon reachable.
#
# A missing DEPENDENCY is not a new problem -- it means exactly what a
# missing CONFIGURATION means everywhere else in this codebase
# (cache-env.sh, run-check.sh, hardened-run.sh, configure-cache.sh,
# version.sh): the thing never ran, so no result says anything about the
# code. Measured 2026-09-18: the first real run died 3 seconds after
# checkout on `ModuleNotFoundError: No module named 'yaml'` in
# validate-checks.py, reported as an ordinary exit 1 with nothing anywhere
# in the 89-99 refusal band -- upstream of every script in this repo that
# knows the band exists. This script is the gate that catches that class of
# failure and reports it correctly: CI is misconfigured, not "something
# failed".
set -uo pipefail

fail() {
  echo "preflight: FATAL -- $1. CI is misconfigured, not merely failing. Refusing to run any check." >&2
  exit 93
}

command -v python3 >/dev/null 2>&1 \
  || fail "python3 is not on PATH"

python3 -c "import yaml" >/dev/null 2>&1 \
  || fail "the Python 'yaml' module is not importable (PyYAML missing) -- every script that reads checks.yaml needs it"

command -v docker >/dev/null 2>&1 \
  || fail "the docker CLI is not on PATH -- hardened-run.sh shells out to it directly"

docker info >/dev/null 2>&1 \
  || fail "the docker daemon is not reachable at DOCKER_HOST=${DOCKER_HOST:-(unset)} -- dind may not be up yet, or the CLI cannot reach it"

echo "preflight: ok -- python3, the yaml module, the docker CLI, and the docker daemon are all present"
