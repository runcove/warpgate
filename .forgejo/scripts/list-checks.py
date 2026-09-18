#!/usr/bin/env python3
"""Print one check name per line, for the workflow's loop."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import checks_lib

for c in checks_lib.load(sys.argv[1]):
    print(c["name"])
