#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${VERSION_SH:-$HERE/../version.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

# --- --validate --------------------------------------------------------
for good in v0.28.6-cove.1 v0.29.0-cove.12 v1.0.0-cove.3; do
  "$SCRIPT" --validate "$good" >/dev/null 2>&1 \
    && ok "accepts $good" || bad "rejected a valid tag: $good"
done

# The git-describe shape must be REFUSED -- it is what we are replacing, and
# it is why Renovate cannot order our versions.
for bad_tag in v0.28.6-75-g50268b2d v0.28.6 cove.1 v0.28.6-cove v0.28.6-cove.0x1; do
  "$SCRIPT" --validate "$bad_tag" >/dev/null 2>&1 \
    && bad "accepted an invalid tag: $bad_tag" || ok "rejects $bad_tag"
done

# --- --sort-key ----------------------------------------------------------
# Ordering: the whole point. -cove.2 must sort after -cove.1, and -cove.10
# after -cove.9.
a=$("$SCRIPT" --sort-key v0.28.6-cove.9); b=$("$SCRIPT" --sort-key v0.28.6-cove.10)
[ "$(printf '%s\n%s\n' "$a" "$b" | sort | tail -1)" = "$b" ] \
  && ok "cove.10 sorts after cove.9" || bad "numeric ordering broken ($a vs $b)"

# A malformed tag must not get a valid-looking sort key: `printf %010d` on a
# non-numeric counter would otherwise silently substitute 0, sorting it below
# every real release. Refuse instead of guessing -- and the refusal must not
# be misread as a missing-argument case (93): the argument IS present, it's
# just not well-formed.
out=$("$SCRIPT" --sort-key v0.28.6-cove.abc 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok "refuses to sort a malformed tag" \
  || bad "produced a sort key for a malformed tag: $out"
[ "$rc" -ne 93 ] && ok "malformed sort-key input is not misreported as a missing argument" \
  || bad "malformed tag misreported as a missing argument (rc=93): $out"

# --- --is-release ----------------------------------------------------------
"$SCRIPT" --is-release v0.28.6-cove.1 >/dev/null 2>&1 \
  && ok "a release tag is a release" || bad "release tag not recognised"
"$SCRIPT" --is-release wip/fork-ci >/dev/null 2>&1 \
  && bad "a branch counted as a release -- ARM would build on every push" \
  || ok "a branch is not a release"

# --- missing operands: the exit-93 contract this codebase shares ---------
# `${2:?}` would kill the script with bash's own generic exit 1,
# indistinguishable from an ordinary failure. Assert the exact code AND this
# script's own message text, not just "rc -ne 0".
for sub in --validate --sort-key --is-release; do
  out=$("$SCRIPT" "$sub" 2>&1); rc=$?
  [ "$rc" -eq 93 ] && ok "$sub with no operand exits 93, not a bare 1" \
    || bad "$sub with no operand did not exit 93 (rc=$rc): $out"
  grep -q "version.sh: FATAL" <<<"$out" \
    && ok "$sub names it as a refusal in this script's own message, not bash's builtin :? text" \
    || bad "$sub did not produce our own refusal message: $out"
done

# --- usage path: no subcommand, and an unrecognised one -------------------
out=$("$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "no subcommand exits 93" \
  || bad "no subcommand did not exit 93 (rc=$rc): $out"
grep -q "usage:" <<<"$out" && ok "no subcommand prints usage" \
  || bad "no subcommand did not print usage: $out"

out=$("$SCRIPT" --bogus 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "an unrecognised subcommand exits 93" \
  || bad "an unrecognised subcommand did not exit 93 (rc=$rc): $out"

# --- --next: driven entirely by throwaway git repos, NEVER by tagging -----
# the shared checkout at /home/tenfourty/repos/warpgate -- several sessions
# share that tree and a stray tag there would look like a real release.
SCRATCH="${TMPDIR:-/tmp}/version-sh-test.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

# --next's remote-completeness check (door 2 of the 96 guard) means every
# case below needs a "remote" it can query -- a second throwaway bare repo,
# never a real network endpoint. push_all keeps one in sync with its clone;
# the incomplete-view and unreachable-remote cases deliberately don't call it
# (that's the point).
push_all() { # $1 = working clone dir, already has an 'origin'
  local branch
  branch=$(git -C "$1" symbolic-ref --short HEAD)
  git -C "$1" push -q origin "$branch" --tags 2>/dev/null
}

REMOTE="$SCRATCH/remote.git"
git init -q --bare "$REMOTE"
REPO="$SCRATCH/repo"
git clone -q "$REMOTE" "$REPO" 2>/dev/null
(cd "$REPO" && git commit -q --allow-empty -m init) >/dev/null

# No upstream tag reachable at all: --next must refuse, not guess a base.
# (Exits before ever reaching the remote check, so no push needed here.)
out=$(cd "$REPO" && "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 95 ] && ok "--next refuses with no upstream tag reachable" \
  || bad "--next did not refuse with no upstream tag (rc=$rc): $out"

# Tag the upstream base and push it: remote and local agree, zero cove
# releases exist on EITHER side -- this is genuinely the first one, using
# the DEFAULT remote name ("origin"), not the VERSION_SH_REMOTE override.
(cd "$REPO" && git tag v0.28.6)
push_all "$REPO"
out=$(cd "$REPO" && "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "v0.28.6-cove.1" ] \
  && ok "--next starts the first cove release at .1 (default remote name)" \
  || bad "--next did not produce v0.28.6-cove.1 (rc=$rc): $out"

# Existing cove releases on the SAME commit, kept in sync with the remote:
# --next must increment past the highest one, not just count them (and not
# trip over --match's glob matching the cove tags themselves -- see
# version.sh's --exclude comment).
(cd "$REPO" && git tag v0.28.6-cove.1 && git tag v0.28.6-cove.9)
push_all "$REPO"
out=$(cd "$REPO" && "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "v0.28.6-cove.10" ] \
  && ok "--next increments past cove.9 to cove.10, not cove.2" \
  || bad "--next did not produce v0.28.6-cove.10 (rc=$rc): $out"

# A cove tag CLOSER to HEAD than the upstream tag must not become "base".
# Without --exclude, `git describe --match 'v[0-9]*.[0-9]*.[0-9]*'` also
# matches "v0.28.6-cove.11" (the glob's [0-9]* is one digit then anything,
# not "digits only"), and describe would return the nearer cove tag as the
# base -- corrupting every version from here on.
REMOTE2="$SCRATCH/remote2.git"
git init -q --bare "$REMOTE2"
REPO2="$SCRATCH/repo2"
git clone -q "$REMOTE2" "$REPO2" 2>/dev/null
(cd "$REPO2" && git commit -q --allow-empty -m base && git tag v0.28.6 \
   && git commit -q --allow-empty -m release && git tag v0.28.6-cove.11) >/dev/null
push_all "$REPO2"
out=$(cd "$REPO2" && VERSION_SH_REMOTE="$REMOTE2" "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 0 ] && [ "$out" = "v0.28.6-cove.12" ] \
  && ok "--next finds the real upstream base past a nearer cove tag" \
  || bad "--next got confused by a nearer cove tag (rc=$rc): $out"

# A shallow clone must refuse rather than silently reissue an existing
# version: it can resolve the base tag from the one commit it has, while
# missing every cove tag the full repo already carries. (Refused by door 1,
# before the remote check -- no working remote needed for this one.)
SHALLOW="$SCRATCH/shallow"
git clone -q --depth 1 "file://$REPO" "$SHALLOW" 2>/dev/null
out=$(cd "$SHALLOW" && "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 96 ] && ok "--next refuses on a shallow clone rather than guessing" \
  || bad "--next did not refuse on a shallow clone (rc=$rc): $out"

# Round 1 review's exact finding: a FULL, non-shallow clone whose local view
# is simply stale -- it fetched the upstream tag, then releases happened on
# the remote afterwards (a long-lived runner workspace; a checkout that
# raced a concurrent push) and it never re-fetched. is-shallow-repository
# says false; without the remote check this reissued an existing cove.1.
REMOTE3="$SCRATCH/remote3.git"
git init -q --bare "$REMOTE3"
SEED3="$SCRATCH/seed3"
git clone -q "$REMOTE3" "$SEED3" 2>/dev/null
(cd "$SEED3" && git commit -q --allow-empty -m base && git tag v0.28.6)
push_all "$SEED3"
STALE="$SCRATCH/stale"
git clone -q "$REMOTE3" "$STALE" 2>/dev/null   # local view frozen here
(cd "$SEED3" && git tag v0.28.6-cove.1 && git tag v0.28.6-cove.9)
push_all "$SEED3"                              # remote moves on without $STALE
out=$(cd "$STALE" && VERSION_SH_REMOTE="$REMOTE3" "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 96 ] && ok "--next refuses a stale-but-non-shallow local view" \
  || bad "--next did not refuse a stale local view (rc=$rc): $out"
# Gated on rc=96 too: a neutered guard's SUCCESS output is "v0.28.6-cove.1",
# which itself contains the substring "cove.1" -- checking the message alone
# would pass by coincidence against exactly the mutant this exists to catch.
[ "$rc" -eq 96 ] && grep -q "v0.28.6-cove.1" <<<"$out" && grep -q "v0.28.6-cove.9" <<<"$out" \
  && ok "names the missing tags in the refusal" \
  || bad "refusal did not name what was missing, or wrong rc (rc=$rc): $out"

# A remote that cannot be reached at all is exactly as untrustworthy as one
# that disagrees -- refuse, don't fall back to trusting local state alone.
out=$(cd "$REPO" && VERSION_SH_REMOTE="$SCRATCH/does-not-exist.git" "$SCRIPT" --next 2>&1); rc=$?
[ "$rc" -eq 96 ] && ok "--next refuses when the remote can't be reached" \
  || bad "--next did not refuse on an unreachable remote (rc=$rc): $out"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
