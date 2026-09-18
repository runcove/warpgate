#!/usr/bin/env python3
"""Look one check up in checks.yaml. Exists so the shell never parses YAML."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import checks_lib


def main(argv):
    path, name = argv[1], argv[2]
    want_reason = "--reason" in argv
    for c in checks_lib.load(path):
        if c["name"] == name:
            if want_reason:
                print(f"{c.get('reason', '').strip()} "
                      f"(review_by: {c.get('review_by', 'unset')})")
            else:
                # compiles_token(), not c['compiles'] directly: the raw YAML
                # value is the Python bool True/False, which an f-string
                # renders as "True"/"False" -- capitalised, and the shell
                # side compares against the lowercase "true"/"false" tokens
                # checks_lib defines as the one true spelling. Interpolating
                # the raw value here would make every compiling check match
                # neither branch downstream and silently run uncapped.
                print(f"{c['state']}|{checks_lib.compiles_token(c)}|{c['command']}")
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
