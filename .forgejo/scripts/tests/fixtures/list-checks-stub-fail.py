#!/usr/bin/env python3
"""Stub list-checks.py that always fails, printing no check names at all --
simulates a checks.yaml that fails checks_lib.load() (or any other reason
list-checks.py might exit non-zero), on a disposable copy of the dependency
graph. Never mutates the real list-checks.py or checks.yaml anywhere in the
shared checkout -- proves run-all-checks.sh's own defence (fix round 1,
Task 7A) against this exact status being swallowed by a process
substitution."""
import sys

print("list-checks-stub-fail: simulated enumeration failure", file=sys.stderr)
sys.exit(1)
