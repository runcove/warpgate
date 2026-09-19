#!/usr/bin/env bash
# Our translation of upstream's .github/workflows/check-schema-compatibility.yml.
#
# WHAT THIS REPLACES. Until now `schema-compat` ran `just openapi-all`, which
# GENERATES the API schema and stops. Upstream generates it, fetches a
# baseline, and runs `oasdiff breaking` between the two. The comparison IS the
# check: without it this check passed whenever generation succeeded and could
# not fail for the reason it exists -- the same defect `check-lockfile.sh` had
# when a missing `jq` read as "zero problems found" (runcove-xais).
#
# THE BASELINE, and why it is not `main`. Upstream triggers on pull_request and
# compares against `main`, which a push-triggered fork branch does not have.
# This fork exists to carry patches on a released upstream, so the question
# worth asking here is "breaking relative to the release we patch" -- and that
# one is answerable on every push, with no PR.
#
# TWO RECORDS OF THAT RELEASE, AND THEY CAN DISAGREE. The tag lives in
# `.forgejo/checks.yaml` as `upstream_tag`, and the release branch encodes it in
# its name (`cove-patches-v0.28.6`; there is a `cove-patches-v0.26.1` too, so
# the name is a live encoding rather than decoration). Nothing keeps them in
# step: a future rebase that updated one and not the other would leave this
# check measuring against the wrong release while staying green. So when the
# branch encodes a tag the two must AGREE, and a disagreement REFUSES rather
# than picking a winner -- a disagreement is exactly the condition under which
# this check's answer is worthless, and a script cannot tell which side is the
# stale one.
#
# THE BASELINE IS READ, NOT BUILT. Upstream generates only in the PR tree and
# compares against the schema file COMMITTED on main; it never rebuilds main.
# We do the same, which is why this check compiles the current tree once rather
# than twice, and never has to build a released tree with today's toolchain.
# The cost is inherited: if the tag's committed schema was already stale against
# the tag's own code, our baseline carries that staleness, exactly as upstream's
# does. That is upstream's tradeoff and we are not diverging from it here.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CHECKS="${CHECKS_FILE:-$HERE/../checks.yaml}"
SEVERITY="${SCHEMA_COMPAT_SEVERITY:-$HERE/../../oasdiff-severity.txt}"

# Test hooks, and the same guard run-check.sh carries for its own (run-check.sh
# lines 15-20). These exist so this script's control flow can be exercised
# without a Rust toolchain or oasdiff, neither of which is present on the
# machine this was written on -- and one of which (`cargo run -p
# warpgate-admin`) is a full compile that must not be started there. Left set
# inside real CI they would quietly replace the very thing being measured, so
# they fail loudly instead of running as a silent no-op.
for var in SCHEMA_COMPAT_GEN SCHEMA_COMPAT_OASDIFF; do
  if [ -n "${!var:-}" ] && { [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${FORGEJO_ACTIONS:-}" ]; }; then
    echo "check-schema-compat: REFUSE -- $var is set while CI/GITHUB_ACTIONS/FORGEJO_ACTIONS is present (exit 93).
That variable exists only so this script can be tested without a toolchain; inside real CI it
would stand in for the generation or the comparison it is meant to be testing. Nothing ran." >&2
    exit 93
  fi
done

OASDIFF="${SCHEMA_COMPAT_OASDIFF:-oasdiff}"
ADMIN_REL="warpgate-web/src/admin/lib/openapi-schema.json"
GATEWAY_REL="warpgate-web/src/gateway/lib/openapi-schema.json"

say()    { echo "check-schema-compat: $*"; }
refuse() { echo "check-schema-compat: REFUSE -- $1 (exit $2)" >&2; exit "$2"; }

# ---------------------------------------------------------------------------
# 1. The baseline: read, cross-checked, and resolved -- all before any build.
# ---------------------------------------------------------------------------
# Order is deliberate. Every refusal this script can raise about WHICH release
# to compare against is raised before the compile starts, so a wrong or
# unreachable tag costs seconds rather than a full Rust build and a queue slot
# on a runner shared with the homelab repo.
[ -f "$CHECKS" ] || refuse "no check list at $CHECKS, so no baseline can be read" 93

# Through checks_lib.upstream_tag() rather than a second YAML parse here: that
# accessor RAISES when the field is missing or empty instead of returning a
# default, and a second parser would be a second thing to keep in step -- which
# is the class of defect this whole check exists to catch.
TAG=$(python3 -c '
import sys
sys.path.insert(0, sys.argv[1])
import checks_lib
print(checks_lib.upstream_tag(sys.argv[2]))
' "$HERE" "$CHECKS" 2>/dev/null)
[ -n "$TAG" ] || refuse "could not read upstream_tag from $CHECKS; there is no baseline to compare against" 93

BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
BRANCH_TAG=""
case "$BRANCH" in cove-patches-v*) BRANCH_TAG="${BRANCH#cove-patches-}" ;; esac

# A branch that encodes no tag is NOT a disagreement. CI also runs on `wip/**`,
# which encodes nothing, and refusing there would refuse every development run.
# But it is not silence either: the run says which cross-check was available, so
# a reader can tell a cross-checked green from an unchecked one without going to
# the repository to work out which kind of branch it was.
if [ -n "$BRANCH_TAG" ] && [ "$BRANCH_TAG" != "$TAG" ]; then
  echo "check-schema-compat: REFUSE -- the two records of our base release disagree (exit 96).
  upstream_tag in $CHECKS : $TAG
  encoded in branch name   : $BRANCH_TAG   (branch $BRANCH)
Neither is preferred. Comparing against the wrong release is worse than not comparing, and
which of these two is the stale one cannot be decided from in here. Nothing was compared." >&2
  exit 96
fi
if [ -n "$BRANCH_TAG" ]; then
  say "baseline $TAG, read from upstream_tag in $(basename "$CHECKS") and agreed by branch $BRANCH."
else
  say "baseline $TAG, read from upstream_tag in $(basename "$CHECKS"); branch '$BRANCH' encodes no tag, so no cross-check was available."
fi

git rev-parse -q --verify "${TAG}^{commit}" >/dev/null 2>&1 \
  || refuse "baseline tag $TAG is not a commit this checkout can read -- a shallow clone, or tags not fetched. Nothing was compared." 96

[ -f "$SEVERITY" ] \
  || refuse "no severity file at $SEVERITY; upstream passes one to oasdiff and without it the thresholds would silently differ from theirs" 93

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) \
  || refuse "not inside a git checkout, so the baseline cannot be extracted" 96

WORK=$(mktemp -d) || refuse "could not create a working directory" 96
trap 'rm -rf "$WORK"' EXIT
BASE_DIR="$WORK/baseline"
mkdir -p "$BASE_DIR"

# git archive, never `cp` from anywhere: this repository is reachable through a
# SYMLINK on the machine where it is developed, and a copy follows the link
# rather than the tree (trap 53). An archive of a TAG also cannot pick up
# uncommitted working-tree state, which is the entire point of a baseline.
# Naming the two paths explicitly, rather than extracting the whole tree, makes
# a tag that simply does not carry these files fail here and say so, instead of
# failing later as "no schema to compare".
git archive "$TAG" -- "$ADMIN_REL" "$GATEWAY_REL" | tar -x -C "$BASE_DIR" \
  || refuse "could not extract the committed schemas of $TAG; that tag may predate these paths" 96

# Prove the thing about to be built is not the thing being compared against it.
# Without this, an extraction that somehow landed in the working tree would
# compare the tree with itself and report "no breaking changes" -- a pass that
# examined nothing, which is this arc's recurring failure in one line.
[ "$(readlink -f "$BASE_DIR")" != "$(readlink -f "$REPO_ROOT")" ] \
  || refuse "the baseline tree IS the working tree; any comparison would be against itself" 96

# ---------------------------------------------------------------------------
# 2. Generate the current schema. Once, in the working tree.
# ---------------------------------------------------------------------------
# DELIBERATE DIVERGENCES from upstream, written down rather than left as
# omissions:
#
#  (a) Upstream runs `just openapi-all`, which is four npm scripts: two that
#      emit the schemas and two that generate TypeScript clients. Only the
#      schemas are compared, and client generation needs openapi-generator-cli,
#      a JAVA tool -- so running it would drag a JVM into the sandbox image to
#      produce artefacts this check never opens. We run the two schema scripts.
#
#  (b) Upstream runs `npm ci` first. These two scripts are each a single
#      `cargo run` redirected to a file (see warpgate-web/package.json), and
#      `npm run` needs only package.json to dispatch them, so the install would
#      be minutes spent on dependencies nothing here reaches for.
#
#  (c) Upstream passes oasdiff `-f githubactions`, which emits GitHub workflow
#      annotations. Our forge does not read those, so we take the default text
#      output, which is what lands in the job log a human actually reads.
#
# `mkdir -p warpgate-web/dist` is NOT a divergence -- upstream does it too, and
# the crates fail to build without that directory present.
#
# Through `npm run` rather than by calling cargo directly, even though each
# script is one cargo command: package.json is upstream's definition of how a
# schema is produced, and inlining it here would be a third copy to keep in step.
generate() { # generate <repo-root>
  local root="$1"
  if [ -n "${SCHEMA_COMPAT_GEN:-}" ]; then
    SCHEMA_ROOT="$root" bash -c "$SCHEMA_COMPAT_GEN"
    return $?
  fi
  mkdir -p "$root/warpgate-web/dist" || return $?
  ( cd "$root/warpgate-web" \
    && npm run openapi:schema:admin \
    && npm run openapi:schema:gateway )
}

generate "$REPO_ROOT" \
  || refuse "could not generate this tree's API schema, so nothing was compared" 96

# ---------------------------------------------------------------------------
# 3. Compare, and say what was compared.
# ---------------------------------------------------------------------------
rc=0
examined=0
for pair in "admin:$ADMIN_REL" "gateway:$GATEWAY_REL"; do
  name="${pair%%:*}"; rel="${pair#*:}"
  base="$BASE_DIR/$rel"; cur="$REPO_ROOT/$rel"
  [ -s "$base" ] || refuse "$TAG carries no $name schema at $rel, so there is nothing to compare against" 99
  [ -s "$cur" ]  || refuse "this tree produced no $name schema at $rel, so there is nothing to compare" 99
  examined=$((examined + 1))
  if "$OASDIFF" breaking --fail-on WARN --severity-levels "$SEVERITY" "$base" "$cur"; then
    say "$name API: no breaking changes against $TAG."
  else
    orc=$?
    # oasdiff exits non-zero BOTH for "breaking changes found" and for its own
    # usage and I/O errors, so a status inside OUR refusal band must not be
    # passed off as a verdict about the schema. Refusing here costs a rerun; the
    # alternative costs a wrong answer wearing the right word.
    [ "$orc" -ge 89 ] && [ "$orc" -le 99 ] \
      && refuse "oasdiff exited $orc on the $name API, inside our refusal band -- reading that as a tool failure, not as a verdict on the schema" 96
    say "$name API: BREAKING changes against $TAG (oasdiff exit $orc)."
    rc=1
  fi
done

# Printed on every run, pass or fail. A green line that does not state its own
# scope cannot be read without going to the repository to find out what it
# covered -- the rule check-lockfile.sh now follows with "examined N lockfile(s)".
say "compared $examined API schema(s) against $TAG, thresholds from $(basename "$SEVERITY")."
exit "$rc"
