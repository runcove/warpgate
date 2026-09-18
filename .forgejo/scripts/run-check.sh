#!/usr/bin/env bash
# Run one check from .forgejo/checks.yaml, in the right environment, with the
# right consequence for failure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHECKS="${CHECKS_FILE:-$HERE/../checks.yaml}"
NAME="${1:?usage: run-check.sh <check-name>}"

# The lookup is done by a helper so the shell never parses YAML.
LOOKUP=$(python3 "$HERE/lookup-check.py" "$CHECKS" "$NAME") || {
  echo "run-check: no check named '$NAME' in $CHECKS" >&2; exit 2; }
STATE=$(cut -d'|' -f1 <<<"$LOOKUP")
COMPILES=$(cut -d'|' -f2 <<<"$LOOKUP")
COMMAND=$(cut -d'|' -f3- <<<"$LOOKUP")

# A lookup that "succeeded" but handed back nothing to run is not a pass --
# running an empty command would silently look identical to a check that ran
# and passed. Refuse instead of pretending.
[ -n "$COMMAND" ] || {
  echo "run-check: lookup for '$NAME' returned no command -- refusing to run nothing as if it passed" >&2
  exit 2
}

STATE="${RUN_CHECK_FORCE_STATE:-$STATE}"

if [ "$STATE" = "excepted" ]; then
  REASON=$(python3 "$HERE/lookup-check.py" "$CHECKS" "$NAME" --reason) || REASON="(reason unavailable)"
  echo "SKIP $NAME — excepted. $REASON"
  exit 0
fi

# Whether a check is capped is a safety decision, not a convenience one: an
# uncapped Rust build on this cluster has already taken the control plane
# down once (2026-09-15). So this defaults to CAPPED and only opts out on the
# one token that unambiguously means "does not compile" -- "true" and
# "unverified" both cap (checks_lib's rule for 'unverified', extended here to
# every other shape too), and so does anything unexpected: empty, garbled, a
# stale "True"/"False" from before compiles_token() existed, or a lookup that
# partially failed. An unrecognised value never gets to mean "safe to run
# uncapped" by accident.
CAPPED=yes
[ "$COMPILES" = "false" ] && CAPPED=no

if [ "${RUN_CHECK_DRY:-}" = "1" ]; then
  if [ "$CAPPED" = "yes" ]; then
    echo "would run via hardened-run: $COMMAND"
  else
    echo "would run directly: $COMMAND"
  fi
  exit 0
fi

if [ -n "${RUN_CHECK_FORCE_RC:-}" ]; then
  rc="$RUN_CHECK_FORCE_RC"
elif [ "$CAPPED" = "yes" ]; then
  "$HERE/hardened-run.sh" --cpus "${CI_CPUS:-4}" --memory "${CI_MEMORY:-7g}" \
    --label "check-$NAME" -- bash -lc "$COMMAND"
  rc=$?
else
  bash -lc "$COMMAND"
  rc=$?
fi

if [ "$rc" -eq 0 ]; then
  echo "PASS $NAME"
  exit 0
fi

if [ "$STATE" = "blocking" ]; then
  echo "FAIL $NAME (blocking) — exit $rc" >&2
  exit "$rc"
fi

echo "FAIL $NAME (report-only, does not fail the job) — exit $rc"
exit 0
