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
# A third and a fourth of the same shape, found 2026-09-19 (runcove-4h0):
# lockfileVersion 1 keeps its tree under `.dependencies` and has no `.packages`
# at all, so this check's filter matched nothing and reported PASS having
# verified not one package; and a file that parses but yields zero entries did
# the same. Both now refuse with 99. And a passing run printed NOTHING -- run
# 529's entire record of this check is the words "PASS lockfile" -- so it now
# prints what it examined, because a pass over two lockfiles and a pass over
# one of them looked identical in the log.
#
# Separately: `find` matching zero lockfiles was silently read the same way
# -- the while loop's body never runs, rc stays 0, "PASS" with nothing
# examined. A check that examined nothing cannot say PASS (trap 3,
# agent_docs/verification-and-gating.md), so a positive count is asserted
# below -- and it exits 99, not 1: exit 1 reads as an ordinary FAIL, which
# asserts the check LOOKED and found a problem. "I examined nothing" is
# neither a pass nor a fail, it is the same "did not run safely" fact 97
# reports for a missing tool, just for a different cause (no source
# delivered into an empty directory is exactly the shape Task 7B's own gap
# would produce today, before it lands: this refuses that instead of
# blaming the code).
set -uo pipefail

for t in jq find; do
  command -v "$t" >/dev/null 2>&1 || {
    echo "check-lockfile.sh: FATAL -- required tool '$t' is not installed. Refusing to run." >&2
    exit 97
  }
done

rc=0
examined=0
checked=0
while IFS= read -r lock; do
  examined=$((examined + 1))

  # The format, before the contents. This check reads `.packages`, which is
  # how lockfileVersion 2 and 3 store every entry -- version 1 has no
  # `.packages` key at all and keeps its tree under `.dependencies`. Fed a
  # version 1 file, the filter below matches nothing, `missing` comes back
  # empty, and the check reports PASS having verified not one package. Same
  # false PASS as the two in the header, one level further in: the loop runs,
  # the file is real, and still nothing is examined.
  ver=$(jq -r '.lockfileVersion // "absent"' "$lock")
  jq_rc=$?
  if [ "$jq_rc" -ne 0 ]; then
    echo "$lock: jq could not read this lockfile (exit $jq_rc) -- cannot verify it, not reporting a pass" >&2
    rc=1
    continue
  fi
  case "$ver" in
    2|3) ;;
    *)
      echo "check-lockfile.sh: FATAL -- $lock has lockfileVersion $ver. This check verifies the \`packages\` map, which only versions 2 and 3 have; on anything else it would examine no entries and report a pass. Refusing instead." >&2
      exit 99
      ;;
  esac

  # Counted, not assumed. A lockfile can parse, carry a version this check
  # understands, and still yield nothing to look at -- truncated, or holding
  # only the root "" entry the filter excludes. "I read a file" is not "I
  # checked a package".
  entries=$(jq -r '[ .packages // {} | to_entries[] | select(.key != "") ] | length' "$lock")
  jq_rc=$?
  if [ "$jq_rc" -ne 0 ]; then
    echo "$lock: jq could not count this lockfile's entries (exit $jq_rc) -- cannot verify it, not reporting a pass" >&2
    rc=1
    continue
  fi
  if [ "$entries" -eq 0 ]; then
    echo "check-lockfile.sh: FATAL -- $lock has lockfileVersion $ver but no package entries to check. Refusing to report a pass on a file nothing was read out of." >&2
    exit 99
  fi
  checked=$((checked + entries))

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
  echo "check-lockfile.sh: FATAL -- found zero package-lock.json files. Refusing to report a pass or a fail: nothing was examined." >&2
  exit 99
fi

# Always, on a pass as much as on a fail. Until 2026-09-19 a green run of this
# check printed NOTHING -- run 529's whole record of it is the two words "PASS
# lockfile" -- so a run that examined both of this repo's lockfiles and a run
# that examined one of them, because only part of the source arrived, left
# identical evidence. A count is the difference between the two, and it costs
# one line. run-check.sh does not capture a check's stdout, so this reaches the
# job log.
echo "check-lockfile.sh: examined $examined lockfile(s), $checked package entries."

exit "$rc"
