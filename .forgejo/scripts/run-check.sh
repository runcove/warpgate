#!/usr/bin/env bash
# Run one check from .forgejo/checks.yaml, in the right environment, with the
# right consequence for failure.
set -uo pipefail

# These hooks exist so this script's control flow (excepted/blocking/
# reporting, capped/uncapped, refusal-band handling) is testable without a
# real check command or a container runtime. Mirrors hardened-run.sh's own
# guard: same three CI markers, same exit code. If any of these leak into a
# real CI run -- via a copied env: block or a prior step's GITHUB_ENV -- they
# silently defeat the very logic they exist to test (the reviewer
# demonstrated FORGEJO_ACTIONS=true RUN_CHECK_FORCE_STATE=blocking
# RUN_CHECK_FORCE_RC=0 printing "PASS clippy" with no command ever run), so
# fail loudly instead of running as a quiet no-op.
for var in RUN_CHECK_DRY RUN_CHECK_FORCE_STATE RUN_CHECK_FORCE_RC; do
  val="${!var:-}"
  if [ -n "$val" ] && { [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${FORGEJO_ACTIONS:-}" ]; }; then
    echo "run-check: FATAL -- $var is set while CI/GITHUB_ACTIONS/FORGEJO_ACTIONS is present.
This variable exists only to test this script without a real check or container runtime; left
set inside real CI it would silently defeat the state/cap logic it is meant to test. Refusing to
run." >&2
    exit 92
  fi
done

HERE="$(cd "$(dirname "$0")" && pwd)"
CHECKS="${CHECKS_FILE:-$HERE/../checks.yaml}"

# Not `"${1:?...}"` -- that form kills the script via bash's own
# parameter-expansion error, exit 1, indistinguishable from an ordinary
# failure. A missing required argument is a refusal like the ones below it.
if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "run-check: FATAL -- usage: run-check.sh <check-name> (required argument missing). Refusing to run." >&2
  exit 93
fi
NAME="$1"

# The lookup is done by a helper so the shell never parses YAML, under a
# timeout so a hung lookup (a wedged interpreter, a filesystem stall on
# CHECKS) fails the job instead of hanging this script forever -- a timeout
# is a refusal, not a pass. RUN_CHECK_LOOKUP_TIMEOUT is a plain tunable, not
# a test hook: a caller raising or lowering it in real CI cannot make an
# unsafe check run uncapped, so it is deliberately not in the CI-leak guard
# above.
LOOKUP_TIMEOUT="${RUN_CHECK_LOOKUP_TIMEOUT:-10}"
LOOKUP=$(timeout "$LOOKUP_TIMEOUT" python3 "$HERE/lookup-check.py" "$CHECKS" "$NAME"); lookup_rc=$?
if [ "$lookup_rc" -eq 124 ]; then
  echo "run-check: FATAL -- lookup for '$NAME' timed out after ${LOOKUP_TIMEOUT}s. Refusing to run blind." >&2
  exit 94
elif [ "$lookup_rc" -ne 0 ]; then
  echo "run-check: no check named '$NAME' in $CHECKS" >&2
  exit 2
fi
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
  REASON=$(timeout "$LOOKUP_TIMEOUT" python3 "$HERE/lookup-check.py" "$CHECKS" "$NAME" --reason) \
    || REASON="(reason unavailable)"
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

# Exit codes 89-99 are hardened-run.sh's reserved "could not run safely"
# band (documented in its own header: 90 cap read-back failed or didn't
# match, 91 container could not be created, 92 a test hook leaked into CI,
# 93 required configuration missing -- and deliberately treated as the
# WHOLE band here, not just those four, because enumerating only the codes
# we know about is how a new one gets misread as an ordinary check result).
# A refusal is not a statement about the check -- it means the check never
# safely ran at all -- so it is NEVER downgraded by `state: reporting` and
# never reached for an `excepted` check (that path already returned above).
# This applies on the uncapped path too: a real check command that happens
# to exit in this band is a coincidence, and misreporting it as a refusal is
# the safe direction of error -- loud and investigable, never silent.
if [ "$rc" -ge 89 ] && [ "$rc" -le 99 ]; then
  echo "REFUSE $NAME — did not run safely (exit $rc, reserved band 89-99). This is not a pass or a fail; investigate before retrying." >&2
  exit "$rc"
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
