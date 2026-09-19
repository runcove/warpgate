#!/usr/bin/env bash
# Reproducible-build checking: NOT IMPLEMENTED. This file exists so that the
# absence is honest rather than pre-armed.
#
# checks.yaml named `.forgejo/scripts/reprotest.sh` as this check's command
# while no such file existed, and had done since the check list was written.
# Nobody noticed, because the check is `state: excepted` and therefore never
# runs. Un-except it and it would have failed with "No such file or directory"
# — an ORDINARY-range failure that no exit code distinguishes from a verdict on
# our code. A fake verdict sitting in the check list waiting for someone to
# enable it (runcove-uw2t).
#
# So this refuses, in the reserved band, and says why. A refusal cannot be
# mistaken for a verdict; that is the whole point of the band.
#
# WHAT IT WOULD TAKE, so the next person does not have to re-derive it.
# Upstream's .github/workflows/reprotest.yml builds twice and compares. For
# that comparison to mean anything the build must be path-independent, and
# ours currently is not: measured 2026-09-19, cargo does NOT expand
# environment variables in config rustflags, so `.cargo/config.toml`'s
# `--remap-path-prefix=$HOME=…` and `--remap-path-prefix=$PWD=…` reach rustc
# with the dollar signs intact and match nothing. Our reproducibility rests on
# `-Zremap-cwd-prefix` alone. Fixing that is the prerequisite, and it is
# tracked with the rest of release-build's environment on runcove-xais.
#
# Deliberately NOT a stub that passes. A check that reports success while
# doing nothing is the exact defect this repository's CI has spent a week
# removing from other checks.
echo "REFUSE reprotest — reproducible-build checking is not implemented (exit 99).
This script is a placeholder that refuses rather than a command that does not exist: the
check list named a missing file, which would have failed in the ordinary range and read
like a verdict on the code. Nothing was examined and nothing was proven.
Prerequisite: release-build's path remapping, which is currently inert (runcove-xais).
Tracked as runcove-uw2t." >&2
exit 99
