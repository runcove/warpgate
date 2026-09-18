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

rc=0
refused=0
failed=0
saw_refusal=0
while read -r name; do
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
done < <(python3 "$HERE/list-checks.py" "$CHECKS")

echo "checks refused: $refused, checks failed: $failed"
exit "$rc"
