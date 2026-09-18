#!/usr/bin/env bash
# Upstream's lockfile.yml: every package-lock.json entry must carry both
# `resolved` and `integrity`. An entry missing either can be substituted.
set -uo pipefail
rc=0
while IFS= read -r lock; do
  missing=$(jq -r '
    [ .packages // {} | to_entries[]
      | select(.key != "")
      | select((.value.resolved // "") == "" or (.value.integrity // "") == "")
      | .key ] | .[]' "$lock")
  if [ -n "$missing" ]; then
    echo "$lock: entries missing resolved or integrity:"
    echo "$missing" | sed 's/^/  /'
    rc=1
  fi
done < <(find . -name package-lock.json -not -path "*/node_modules/*")
exit "$rc"
