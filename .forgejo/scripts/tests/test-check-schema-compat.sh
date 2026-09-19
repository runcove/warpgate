#!/usr/bin/env bash
# check-schema-compat.sh replaces a check that generated a schema and stopped
# with one that compares it against the release we patch. That comparison is
# the only reason the check exists, so these tests are mostly about proving it
# can FAIL -- and that when it passes, it passed for the right reason.
#
# What is stubbed, and what that costs. Generation is `cargo run -p
# warpgate-admin`, a full Rust build that must not run on this machine, and
# oasdiff is not installed here. Both are therefore replaced through the
# script's own test hooks. That means these tests prove the PLUMBING -- which
# file is handed over as the baseline, which as the current one, in which
# order, and what each exit status is read to mean. They do NOT prove that
# oasdiff detects breaking changes; that is oasdiff's job and no stub of mine
# can stand in for it. Saying so here rather than letting a green suite imply
# otherwise is the whole point of writing it down.
#
# The stub comparator is one program used in both directions: identical files
# exit 0, differing files exit 1. A stub that always failed would satisfy every
# "detects a change" assertion on its own, so each of those is paired with a
# control run where the same stub sees identical inputs and the script passes.
# The verdict comes from the DIFFERENCE between the two runs, never from one
# run looking right.
set -uo pipefail

# FOUND BY CI RUN 580, THE SELFTEST STEP'S FIRST FULL RUN. Every test below
# drives check-schema-compat.sh through its own hooks, and that script refuses
# 93 outright when a hook is set while CI/GITHUB_ACTIONS/FORGEJO_ACTIONS is
# present -- correctly, since inside a real run a hook would stand in for the
# comparison being measured. So this suite could pass only where no CI marker
# was set, i.e. everywhere except the one place it now runs. Six assertions
# failed in CI while passing on a development host.
#
# Clearing the markers here is the same fix test-hardened-run.sh already
# carries for the same reason. It does not weaken the leak check below: that
# loop sets each marker EXPLICITLY on the command it is testing, which is the
# only honest way to test a guard about them anyway -- an ambient variable
# that happens to satisfy a precondition is not a test of that precondition.
unset CI GITHUB_ACTIONS FORGEJO_ACTIONS

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${CHECK_SCHEMA_COMPAT:-$HERE/../check-schema-compat.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

[ -x "$SCRIPT" ] || { echo "  FAIL  $SCRIPT is not executable"; exit 1; }

ADMIN_REL="warpgate-web/src/admin/lib/openapi-schema.json"
GATEWAY_REL="warpgate-web/src/gateway/lib/openapi-schema.json"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- the stubs ------------------------------------------------------------
# oasdiff stand-in: records the argv it was handed (so the tests can assert
# WHICH file went in which position) and compares the last two arguments.
cat > "$TMP/oasdiff-stub" <<'STUB'
#!/usr/bin/env bash
# argv: breaking --fail-on WARN --severity-levels <sev> <base> <cur>
cur="${!#}"
base_i=$(( $# - 1 )); base="${!base_i}"
echo "$base -> $cur" >> "$OASDIFF_LOG"
if cmp -s "$base" "$cur"; then echo "stub-oasdiff: identical"; exit 0; fi
echo "stub-oasdiff: differs"; exit 1
STUB
chmod +x "$TMP/oasdiff-stub"

# oasdiff stand-in that exits inside OUR refusal band, for the one case where
# a tool failure must not be read as a verdict about the schema.
cat > "$TMP/oasdiff-band" <<'STUB'
#!/usr/bin/env bash
exit 94
STUB
chmod +x "$TMP/oasdiff-band"

# Generation stand-in. Touches a marker so a test can tell "generation ran"
# from "the script refused before reaching it", then writes whatever content
# the calling test asked for -- or leaves the tree alone when asked for
# nothing, which simulates a generator that reproduced what is committed.
cat > "$TMP/gen-stub" <<'STUB'
#!/usr/bin/env bash
set -u
: > "$GEN_MARKER"
[ -n "${GEN_CONTENT:-}" ] || exit 0
for rel in warpgate-web/src/admin/lib/openapi-schema.json \
           warpgate-web/src/gateway/lib/openapi-schema.json; do
  mkdir -p "$(dirname "$SCHEMA_ROOT/$rel")"
  printf '%s\n' "$GEN_CONTENT" > "$SCHEMA_ROOT/$rel"
done
STUB
chmod +x "$TMP/gen-stub"

cat > "$TMP/gen-fail" <<'STUB'
#!/usr/bin/env bash
: > "$GEN_MARKER"
echo "stub: generation exploded" >&2
exit 3
STUB
chmod +x "$TMP/gen-fail"

SEV="$TMP/severity.txt"
printf 'response-property-enum-value-added info\n' > "$SEV"

# --- a disposable repository ----------------------------------------------
# Never the real checkout: these tests commit, tag and rewrite schema files,
# and this repository is reachable through a symlink where it is developed.
# make_repo <dir> <branch> <tagged-content> <head-content>
make_repo() {
  local dir="$1" branch="$2" tagged="$3" head="$4"
  rm -rf "$dir"; mkdir -p "$dir"
  ( cd "$dir"
    git init -q -b "$branch" .
    git config user.email t@example.invalid
    git config user.name  tester
    for rel in "$ADMIN_REL" "$GATEWAY_REL"; do
      mkdir -p "$(dirname "$rel")"; printf '%s\n' "$tagged" > "$rel"
    done
    git add -A && git commit -qm "baseline"
    git tag v9.9.9
    # A second resolvable tag on the same commit. The disagreement test needs
    # the tag it disagrees ABOUT to exist: found by mutation, 2026-09-19 --
    # with only v9.9.9 present, disabling the disagreement refusal outright
    # still produced a 96, because the run fell through to "that tag does not
    # resolve". Two different conditions wearing one exit code, which is this
    # arc's recurring defect appearing inside the test for it.
    git tag v0.0.1
    if [ "$head" != "$tagged" ]; then
      for rel in "$ADMIN_REL" "$GATEWAY_REL"; do printf '%s\n' "$head" > "$rel"; done
      git add -A && git commit -qm "diverge"
    fi ) >/dev/null
}

# checks_file <path> <tag-or-empty>
checks_file() {
  if [ -n "$2" ]; then printf 'upstream_tag: %s\nchecks: []\n' "$2" > "$1"
  else printf 'checks: []\n' > "$1"; fi
}

# run <repo> <checks> [env assignments...] -- captures stdout+stderr and rc
run() {
  local repo="$1" checks="$2"; shift 2
  OASDIFF_LOG="$TMP/oasdiff.log"; : > "$OASDIFF_LOG"
  GEN_MARKER="$TMP/gen.marker"; rm -f "$GEN_MARKER"
  out=$(cd "$repo" && env OASDIFF_LOG="$OASDIFF_LOG" GEN_MARKER="$GEN_MARKER" \
        CHECKS_FILE="$checks" SCHEMA_COMPAT_SEVERITY="$SEV" \
        SCHEMA_COMPAT_OASDIFF="$TMP/oasdiff-stub" \
        SCHEMA_COMPAT_GEN="$TMP/gen-stub" \
        "$@" "$SCRIPT" 2>&1); rc=$?
}

CHECKS_OK="$TMP/checks-ok.yaml";  checks_file "$CHECKS_OK" v9.9.9
CHECKS_NOTAG="$TMP/checks-no.yaml"; checks_file "$CHECKS_NOTAG" ""
CHECKS_OTHER="$TMP/checks-other.yaml"; checks_file "$CHECKS_OTHER" v0.0.1

echo "== the comparison can fail, and the baseline is the tag =="

# The control. Tag and working tree carry the same schema, so the same stub
# comparator sees identical inputs. Without this run, the failing case below
# would also be satisfied by a comparator hardwired to fail.
make_repo "$TMP/same" cove-patches-v9.9.9 '{"v":1}' '{"v":1}'
run "$TMP/same" "$CHECKS_OK"
[ "$rc" -eq 0 ] && ok "unchanged schema against its tag: passes (0)" \
  || bad "unchanged schema should pass, got rc=$rc: $out"
grep -q "compared 2 API schema(s) against v9.9.9" <<<"$out" \
  && ok "a passing run states its own scope" \
  || bad "passing run does not say what it compared: $out"

# The failing case. The working tree's schema differs from the tag's, and
# nothing else about the run changes. This is also the assertion that proves
# the baseline came from the TAG: a script that compared the working tree with
# itself would see two identical files here and pass.
make_repo "$TMP/diff" cove-patches-v9.9.9 '{"v":1}' '{"v":2,"breaking":true}'
run "$TMP/diff" "$CHECKS_OK"
[ "$rc" -eq 1 ] && ok "changed schema against its tag: fails (1), not a refusal" \
  || bad "changed schema should fail with 1, got rc=$rc: $out"
grep -q "BREAKING" <<<"$out" && ok "the failing run says which API broke" \
  || bad "failing run does not name the break: $out"

# Argument order. Swapped, oasdiff answers the opposite question and every
# assertion above still holds, because the stub's comparison is symmetric.
# Nothing else in this suite can catch that.
# The baseline's directory is the script's own mktemp, NOT under $TMP, so this
# pattern must not assume the two share a root -- it asserts only that the left
# argument is an extracted baseline and the right one is the checkout itself.
grep -q "/baseline/.*/admin/.*openapi-schema.json -> $TMP/diff/.*/admin/.*openapi-schema.json" "$TMP/oasdiff.log" \
  && ok "oasdiff is handed the baseline first and the current tree second" \
  || bad "oasdiff argument order is wrong or unreadable: $(cat "$TMP/oasdiff.log")"

# The baseline is read, never rebuilt: generation runs once, in the working
# tree. A second generation would mean building a released tree with today's
# toolchain, which upstream does not do either.
[ "$(grep -c . "$TMP/oasdiff.log")" -eq 2 ] \
  && ok "two APIs compared, one generation" \
  || bad "expected 2 comparisons, got: $(cat "$TMP/oasdiff.log")"

echo "== the two records of the base release =="

# The disagreement case: checks.yaml says v0.0.1, the branch name says v9.9.9.
make_repo "$TMP/dis" cove-patches-v9.9.9 '{"v":1}' '{"v":1}'
run "$TMP/dis" "$CHECKS_OTHER"
[ "$rc" -eq 96 ] && ok "disagreeing records: refuses (96)" \
  || bad "disagreement should refuse with 96, got rc=$rc: $out"
# On the refusal's own words, not merely on 96 and the presence of two
# strings: several other conditions also exit 96, and the run's opening line
# names both tags anyway, so the weaker assertions were satisfied by a
# completely different code path.
grep -q "records of our base release disagree" <<<"$out" \
  && ok "and refuses FOR the disagreement, not for some other 96" \
  || bad "the 96 did not come from the disagreement: $out"
grep -q "upstream_tag in .*: v0.0.1" <<<"$out" && grep -q "branch name *: v9.9.9" <<<"$out" \
  && ok "the refusal prints BOTH values against their sources, so a human can see which is stale" \
  || bad "refusal does not attribute both tags to their sources: $out"
grep -q "agreed by branch" <<<"$out" \
  && bad "a disagreeing run still claimed the branch agreed: $out" \
  || ok "and never claims agreement"
[ ! -f "$TMP/gen.marker" ] \
  && ok "a disagreement refuses before spending a build" \
  || bad "generation ran despite an unresolvable baseline"

# A branch that encodes no tag is not a disagreement -- CI also runs on wip/**.
make_repo "$TMP/wip" wip/fork-ci '{"v":1}' '{"v":1}'
run "$TMP/wip" "$CHECKS_OK"
[ "$rc" -eq 0 ] && ok "a branch encoding no tag: runs, does not refuse" \
  || bad "wip branch should not refuse, got rc=$rc: $out"
grep -q "encodes no tag, so no cross-check was available" <<<"$out" \
  && ok "and says the cross-check was unavailable rather than implying one happened" \
  || bad "wip run does not distinguish itself from a cross-checked run: $out"

# Agreement is stated, so a cross-checked green is readable as one.
run "$TMP/same" "$CHECKS_OK"
grep -q "agreed by branch cove-patches-v9.9.9" <<<"$out" \
  && ok "an agreeing run names the branch that agreed" \
  || bad "agreement is not reported: $out"

echo "== refusals: could not run, never ran =="

run "$TMP/same" "$CHECKS_NOTAG"
[ "$rc" -eq 93 ] && ok "no upstream_tag in the check list: refuses (93)" \
  || bad "missing upstream_tag should refuse with 93, got rc=$rc: $out"

run "$TMP/same" "$TMP/does-not-exist.yaml"
[ "$rc" -eq 93 ] && ok "no check list at all: refuses (93)" \
  || bad "missing checks file should refuse with 93, got rc=$rc: $out"

# A tag named in checks.yaml that this checkout cannot resolve -- a shallow
# clone, or tags not fetched. It must refuse, not compare against nothing.
CHECKS_GHOST="$TMP/checks-ghost.yaml"; checks_file "$CHECKS_GHOST" v7.7.7
make_repo "$TMP/ghost" wip/fork-ci '{"v":1}' '{"v":1}'
run "$TMP/ghost" "$CHECKS_GHOST"
[ "$rc" -eq 96 ] && ok "unresolvable tag: refuses (96)" \
  || bad "unresolvable tag should refuse with 96, got rc=$rc: $out"
# On the message, not just the code. `git archive` would also refuse with 96 a
# few lines later, so without this the rev-parse guard could be deleted
# outright and nothing here would notice -- it earns its place by saying WHY
# the tag is unreachable, which git archive's own error does not.
grep -q "shallow clone, or tags not fetched" <<<"$out" \
  && ok "and explains why the tag is unreachable, rather than only that it is" \
  || bad "the refusal came from somewhere else, or lost its explanation: $out"
[ ! -f "$TMP/gen.marker" ] \
  && ok "and refuses before spending a build" \
  || bad "generation ran for a tag that does not resolve"

run "$TMP/same" "$CHECKS_OK" SCHEMA_COMPAT_SEVERITY="$TMP/no-such-severity.txt"
[ "$rc" -eq 93 ] && ok "no severity file: refuses (93) rather than using oasdiff's defaults" \
  || bad "missing severity file should refuse with 93, got rc=$rc: $out"

run "$TMP/same" "$CHECKS_OK" SCHEMA_COMPAT_GEN="$TMP/gen-fail"
[ "$rc" -eq 96 ] && ok "generation fails: refuses (96)" \
  || bad "failed generation should refuse with 96, got rc=$rc: $out"
grep -q "nothing was compared" <<<"$out" \
  && ok "and says nothing was compared, rather than reporting a verdict" \
  || bad "failed generation does not say the comparison never happened: $out"

# oasdiff's own failures share the non-zero space with its verdicts. A status
# inside our refusal band must not come back out as a statement about the API.
run "$TMP/same" "$CHECKS_OK" SCHEMA_COMPAT_OASDIFF="$TMP/oasdiff-band"
[ "$rc" -eq 96 ] && ok "oasdiff exits inside the refusal band: refuses (96)" \
  || bad "a banded oasdiff exit should refuse with 96, got rc=$rc: $out"
grep -qi "breaking changes" <<<"$out" \
  && bad "a tool failure was reported as a verdict about the schema: $out" \
  || ok "and is not reported as a verdict about the schema"

echo "== the test hooks cannot leak into a real run =="
# run-check.sh carries this guard for its own hooks; without it here, a hook
# left set in CI would silently replace the very thing being measured.
leaks=0
for hook in SCHEMA_COMPAT_GEN SCHEMA_COMPAT_OASDIFF; do
  for flag in CI GITHUB_ACTIONS FORGEJO_ACTIONS; do
    o=$(cd "$TMP/same" && env CHECKS_FILE="$CHECKS_OK" "$hook=/bin/true" "$flag=1" "$SCRIPT" 2>&1); r=$?
    if [ "$r" -eq 93 ] && grep -q "$hook" <<<"$o"; then continue; fi
    bad "$hook under $flag: expected a 93 naming the hook, got rc=$r: $o"
    leaks=$((leaks + 1))
  done
done
[ "$leaks" -eq 0 ] && ok "all 6 hook/marker pairs refuse with 93 and name the hook"
# And the mirror: with no CI marker set, the hooks must still WORK -- a guard
# that refused unconditionally would satisfy the six assertions above while
# making every test in this file unrunnable, so it has to be shown not to.
run "$TMP/same" "$CHECKS_OK"
[ "$rc" -eq 0 ] && [ -f "$TMP/gen.marker" ] \
  && ok "outside CI the same hooks are honoured, so the guard is a guard and not a refusal" \
  || bad "hooks do not work outside CI, so the six assertions above prove nothing: rc=$rc $out"

[ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
