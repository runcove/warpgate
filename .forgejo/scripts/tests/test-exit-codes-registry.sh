#!/usr/bin/env bash
# Every `exit 9[0-9]` site in .forgejo/scripts/*.{sh,py} must be named in
# EXIT_CODES.md's row for that code -- the registry's whole point is that it
# is CHECKED, not just written and trusted. It went stale within hours of
# being created (missed preflight.sh's 93, added the same day by a
# different session) precisely because it was a grep of a moving tree,
# presented as a fact instead of a checked one. This test is the fix for
# the CLASS of that mistake, not just the one missing row -- the same
# staleness hardened-run.sh's own inline list had in Round 1, in its third
# costume in one day.
#
# Scope, deliberately narrow, both halves declared on purpose (a declared
# gap is a decision; an undeclared one is an assumption nobody made):
#
#   1. Only .forgejo/scripts/*.sh and *.py DIRECTLY -- not tests/, and not
#      recursive. tests/ is excluded because those files contain
#      `exit 9[0-9]` as ASSERTIONS about an expected code (e.g.
#      `[ "$rc" -eq 93 ]`), not allocations; demanding a registry row for a
#      test fixture would be nonsense. If a script under some NEW
#      subdirectory ever allocates a code, this check will not see it --
#      widen the discovery glob deliberately if that happens, don't just
#      notice later that it did.
#
#   2. This greps the literal bash spelling `exit N`, not Python's
#      `sys.exit(N)`. No .py file allocates a 9x code today (checked
#      2026-09-18: `grep -rn 'sys.exit(9\|exit(9' --include=*.py` is empty).
#      The day one does, this check needs a second pattern and will not
#      warn you that it needs one.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS_DIR="$HERE/.."
REGISTRY="${EXIT_CODES_MD:-$SCRIPTS_DIR/EXIT_CODES.md}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

if [ ! -f "$REGISTRY" ]; then
  echo "test-exit-codes-registry: FATAL -- registry not found at $REGISTRY. Refusing to run." >&2
  exit 93
fi

checked=0
while IFS= read -r -d '' file; do
  base="$(basename "$file")"
  while IFS= read -r code; do
    [ -z "$code" ] && continue
    checked=$((checked + 1))
    row=$(grep -E "^\| ${code} \|" "$REGISTRY")
    if [ -z "$row" ]; then
      bad "$base allocates $code and $code has no row at all in $(basename "$REGISTRY")"
      continue
    fi
    # The Script column ONLY -- field 3 of the pipe-delimited row. Matching
    # against the whole row is exactly the non-discriminating check this
    # arc keeps finding: the Meaning column's prose can (and here, does)
    # mention a script's name too, so a row that dropped that script from
    # its Script column but still explains it in prose would pass by
    # coincidence -- verified by mutating this exact case before trusting
    # this test.
    script_col=$(awk -F'|' '{print $3}' <<<"$row")
    if grep -q "\`${base}\`" <<<"$script_col"; then
      ok "$base's $code is listed in the $code row"
    else
      bad "$base allocates $code and is not named in the $code row's Script column: $row"
    fi
  done < <(grep -ohE "exit 9[0-9]" "$file" | awk '{print $2}' | sort -u)
done < <(find "$SCRIPTS_DIR" -maxdepth 1 -type f \( -name "*.sh" -o -name "*.py" \) -print0 | sort -z)

# A gate proven only by finding nothing is not proven: if discovery itself
# broke (wrong dir, glob typo), this would silently report zero mismatches
# and look identical to "everything is correctly registered".
[ "$checked" -gt 0 ] || bad "found zero exit 9x sites to check at all -- the discovery glob is almost certainly broken, not this codebase suddenly refusal-free"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
