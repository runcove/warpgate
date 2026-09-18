#!/usr/bin/env bash
# Upstream's lockfile.yml: every package-lock.json entry must carry both
# `resolved` and `integrity`. An entry missing either can be substituted.
#
# Proven false-PASS (2026-09-18, Task 7A Step 2A): jq missing was silently
# read as "zero problems found", because `missing=$(jq ...)`'s own exit
# status was never checked -- the 127 died inside the substitution, `[ -n
# "$missing" ]` was false, `rc` stayed 0. Fixed by verifying jq (and find,
# which feeds the loop below) up front and refusing with 97 -- run-check.sh's
# own code for "a tool this check requires is not installed" -- before any
# substitution runs, so this refuses the same way whether it's driven by
# run-check.sh's own `tools:` precondition or run by hand.
#
# Separately: `find` matching zero lockfiles was silently read the same way
# -- the while loop's body never runs, rc stays 0, "PASS" with nothing
# examined. A check that examined nothing cannot say PASS (trap 3,
# agent_docs/verification-and-gating.md), so a positive count is asserted
# below.
set -uo pipefail

for t in jq find; do
  command -v "$t" >/dev/null 2>&1 || {
    echo "check-lockfile.sh: FATAL -- required tool '$t' is not installed. Refusing to run." >&2
    exit 97
  }
done

rc=0
examined=0
while IFS= read -r lock; do
  examined=$((examined + 1))
  missing=$(jq -r '
    [ .packages // {} | to_entries[]
      | select(.key != "")
      | select((.value.resolved // "") == "" or (.value.integrity // "") == "")
      | .key ] | .[]' "$lock")
  jq_rc=$?
  if [ "$jq_rc" -ne 0 ]; then
    echo "$lock: jq could not read this lockfile (exit $jq_rc) -- cannot verify it, not reporting a pass" >&2
    rc=1
    continue
  fi
  if [ -n "$missing" ]; then
    echo "$lock: entries missing resolved or integrity:"
    echo "$missing" | sed 's/^/  /'
    rc=1
  fi
done < <(find . -name package-lock.json -not -path "*/node_modules/*")

if [ "$examined" -eq 0 ]; then
  echo "check-lockfile.sh: found zero package-lock.json files -- cannot verify anything, refusing to report a pass with nothing examined" >&2
  exit 1
fi

exit "$rc"
