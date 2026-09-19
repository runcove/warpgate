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
#   2. Discovery is a LIST OF SPELLINGS, not an understanding of the code.
#      It knows two: the literal `exit N`, and a refusal helper called with
#      the code as its last argument (`refuse "..." 97`). It does not know
#      Python's `sys.exit(N)` -- no .py file allocates a 9x code today
#      (checked 2026-09-18: `grep -rn 'sys.exit(9\|exit(9' --include=*.py`
#      is empty) -- and it will not know a third bash spelling either.
#
#      The second spelling was added 2026-09-19, and the reason is the point
#      of this whole file: check-schema-compat.sh raises 93, 96 and 99
#      through a `refuse` helper. The literal grep saw its two bare
#      `exit 93`/`exit 96` lines and MISSED both 99s entirely -- so the
#      registry check reported a partial answer in the voice of a complete
#      one. A probe reports the spellings it knows; it can never report a
#      spelling it was never taught. The fixture below is what stops that
#      from being an assumption again: it contains one code per recognised
#      spelling, and discovery has to find all of them.
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

# The one place discovery is defined. Both this test's scan of the real
# scripts and the fixture assertion below go through it, so the fixture
# proves something about the scan that actually runs.
codes_in() {
  # Whole-line comments are dropped first: that is where these files discuss
  # codes in prose, and scanning them would demand a registry row for every
  # code anyone ever mentioned. A 9x inside a string or an argument is still
  # picked up -- a declared imprecision that errs toward a loud false alarm
  # rather than a silent miss.
  local body; body=$(grep -v '^[[:space:]]*#' "$1")
  {
    grep -ohE "\bexit 9[0-9]\b" <<<"$body" | awk '{print $2}'
    grep -ohE "\b(refuse|die|abort|bail)\b .* 9[0-9]$" <<<"$body" | awk '{print $NF}'
  } | sort -u
}

# --- does discovery see what it claims to see? ----------------------------
# Without this, a typo in either pattern makes the whole file report "every
# allocation is registered" while looking at half of them -- indistinguishable
# from the healthy state, which is the failure this arc keeps meeting.
FIXTURE="$HERE/fixtures/exit-code-spellings.sh"
if [ ! -f "$FIXTURE" ]; then
  bad "no discovery fixture at $FIXTURE -- the scan below is unverified"
else
  found=$(codes_in "$FIXTURE" | tr '\n' ' ' | sed 's/ $//')
  # Exact, not "contains": a scan that returned every number in the file would
  # satisfy a contains-check while telling you nothing about either pattern.
  [ "$found" = "91 92 94" ] \
    && ok "discovery finds both spellings, ignores comments, and over-reports only where declared" \
    || bad "discovery fixture expected '91 92 94', got '$found' -- see the fixture for what each code stands for"
  grep -q "93" <<<"$found" \
    && bad "discovery read a whole-line comment as an allocation; it will demand rows for codes nobody allocated" \
    || ok "and a code discussed only in a comment is not read as an allocation"
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
  done < <(codes_in "$file")
done < <(find "$SCRIPTS_DIR" -maxdepth 1 -type f \( -name "*.sh" -o -name "*.py" \) -print0 | sort -z)

# A gate proven only by finding nothing is not proven: if discovery itself
# broke (wrong dir, glob typo), this would silently report zero mismatches
# and look identical to "everything is correctly registered".
[ "$checked" -gt 0 ] || bad "found zero exit 9x sites to check at all -- the discovery glob is almost certainly broken, not this codebase suddenly refusal-free"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
