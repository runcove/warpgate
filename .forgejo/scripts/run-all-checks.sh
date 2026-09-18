#!/usr/bin/env bash
# Run every check named in checks.yaml, one at a time, and decide the job's
# own exit code.
#
# A refusal (run-check.sh's reserved 89-99 band -- "did not run safely") is a
# different fact from an ordinary failure ("ran and failed"): a refusal means
# nothing was proven either way, while a failure means the check ran and the
# answer was no. So once any check refuses, ITS code is what this script
# exits with, and nothing after it -- another refusal, or an ordinary
# failure -- overwrites that. Without this, a run where three checks refused
# and one genuinely failed would report only the last one's code, reading as
# "one failure" when actually nothing downstream of the first refusal was
# ever safely checked at all.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECKS="${CHECKS_FILE:-$HERE/../checks.yaml}"

# Fix round 1 (Task 7A): the enumeration itself must not be a silent zero.
# `while read ... done < <(python3 list-checks.py ...)` hid list-checks.py's
# own exit status from the loop -- a checks.yaml that failed to load would
# run zero iterations and this script would report "refused: 0, failed: 0"
# with exit 0: a false green covering the ENTIRE suite, the same defect
# check-lockfile.sh had for one check, one level up. Captured into a plain
# variable instead, so its status is checked directly, and the enumerated
# count is asserted positive afterwards too -- belt and suspenders,
# matching Step 2A's own rule that a check (or a check-runner) that
# examined nothing cannot say PASS. Both refuse with 99, the same code
# check-lockfile.sh uses for "found nothing to examine" -- this is that
# condition one level up, not a different one.
NAMES=$(python3 "$HERE/list-checks.py" "$CHECKS"); list_rc=$?
if [ "$list_rc" -ne 0 ]; then
  echo "run-all-checks: FATAL -- list-checks.py failed (exit $list_rc) reading $CHECKS -- cannot enumerate checks. Refusing to report a result with nothing examined." >&2
  exit 99
fi

rc=0
refused=0
failed=0
saw_refusal=0
count=0
while IFS= read -r name; do
  [ -z "$name" ] && continue
  count=$((count + 1))
  echo "::group::$name"
  "$HERE/run-check.sh" "$name"; check_rc=$?
  echo "::endgroup::"
  if [ "$check_rc" -ne 0 ]; then
    if [ "$check_rc" -ge 89 ] && [ "$check_rc" -le 99 ]; then
      refused=$((refused + 1))
      if [ "$saw_refusal" -eq 0 ]; then
        rc="$check_rc"
        saw_refusal=1
      fi
    else
      failed=$((failed + 1))
      if [ "$saw_refusal" -eq 0 ]; then
        rc="$check_rc"
      fi
    fi
  fi
done <<<"$NAMES"

# Defence in depth: checks_lib.load() already refuses an empty `checks:`
# list, so list-checks.py exiting 0 with zero names printed should be
# unreachable through a real checks.yaml -- but "should be unreachable" is
# exactly the assumption this whole task exists to stop trusting.
if [ "$count" -eq 0 ]; then
  echo "run-all-checks: FATAL -- enumerated zero checks from $CHECKS. Refusing to report a result with nothing examined." >&2
  exit 99
fi

echo "checks refused: $refused, checks failed: $failed"
exit "$rc"
