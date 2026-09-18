#!/usr/bin/env python3
"""Stub list-checks.py that exits 0 but enumerates nothing -- tests
run-all-checks.sh's positive-count assertion in isolation from its
exit-status check above. checks_lib.load() already refuses an empty
`checks:` list, so this exact shape (a load that "succeeds" yet enumerates
zero checks) should be unreachable through a real checks.yaml today; this
proves the defence-in-depth guard fires anyway, on a disposable copy of the
dependency graph, never the real checkout."""
import sys

sys.exit(0)
