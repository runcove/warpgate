#!/usr/bin/env python3
"""Stub for lookup-check.py that never returns.

Exercises run-check.sh's own timeout wrapper around the lookup call -- not
lookup-check.py's correctness, which every other case in test-run-check.sh
already covers against the real script. Symlinked in as `lookup-check.py`
next to a symlinked `run-check.sh` in a throwaway directory, so `HERE`
resolves there and run-check.sh picks this stub up instead of the real one.

LOOKUP_HANG_SECONDS controls how long it sleeps (default 30s -- long enough
that no sane timeout lets it return on its own).
"""
import os
import time

time.sleep(int(os.environ.get("LOOKUP_HANG_SECONDS", "30")))
