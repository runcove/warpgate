#!/usr/bin/env bash
# v<upstream>-cove.<n>: upstream's version, then our own release counter on
# top of it. Replaces `git describe` output (e.g. v0.28.6-75-g50268b2d),
# which changes on every commit and which nothing can order -- measured
# 2026-09-18: Renovate authenticates, fetches, and proposes nothing, because
# "-75-g50268b2d" and "-81-ga71a1160" are not comparable.
#
# --validate and --is-release are deliberately the same test: a well-formed
# release tag IS what triggers the ARM build (see ci.yml). One regex, both
# branches use it below, so they cannot drift apart.
#
# Exit codes 89-99 join the same reserved "could not run safely" band as
# cache-env.sh, run-check.sh, hardened-run.sh and configure-cache.sh -- the
# thing never ran, rather than ran and failed. 93 keeps its meaning from
# those four scripts: a required argument (here, the subcommand or its
# operand) is missing or unrecognised. This script adds two more of its own:
#   95 -- --next found no upstream vX.Y.Z tag reachable from HEAD, so there
#         is no base to build a version on.
#   96 -- --next found no existing <base>-cove.* tag, but cannot tell "no
#         cove release exists yet for this base" from "this clone's tags are
#         incomplete" (a shallow clone, a fetch without --tags, a checkout
#         that skipped them). The two look byte-identical, and reissuing a
#         version number that already exists publishes over a release, so
#         this refuses rather than guesses. A refusal costs a rerun; a
#         collision costs a release.
#
# --validate's and --sort-key's own 0/1 exits are a separate, narrower
# contract ("well-formed or not") that predates this file's use of the
# 89-99 band, and are unaffected by it.
set -uo pipefail

RE='^v[0-9]+\.[0-9]+\.[0-9]+-cove\.[1-9][0-9]*$'
is_valid_tag() { [[ "$1" =~ $RE ]]; }

USAGE="usage: version.sh --validate <tag> | --sort-key <tag> | --is-release <ref> | --next"

# Not `"${2:?...}"` anywhere below -- that form kills the script via bash's
# own parameter-expansion error, exit 1, indistinguishable from an ordinary
# failure and outside this codebase's exit-code contract (the same defect
# already fixed in cache-env.sh, run-check.sh, hardened-run.sh and
# configure-cache.sh). A missing required operand is a refusal like theirs,
# so it gets the same code: 93. $1 here is the subcommand name, only used to
# name the problem in the message.
require_operand() {
  if [ $# -lt 2 ] || [ -z "${2:-}" ]; then
    echo "version.sh: FATAL -- usage: version.sh $1 <tag> (required argument missing). Refusing to run." >&2
    exit 93
  fi
}

case "${1:-}" in
  --validate)
    require_operand --validate "${2:-}"
    is_valid_tag "$2" && exit 0 || exit 1
    ;;

  --is-release)
    require_operand --is-release "${2:-}"
    is_valid_tag "$2" && exit 0 || exit 1
    ;;

  --sort-key)
    require_operand --sort-key "${2:-}"
    tag="$2"
    # Validate before deriving a key. `printf %010d` on a non-numeric
    # counter (e.g. a hand-edited "v0.28.6-cove.abc") fails and silently
    # substitutes 0, which sorts below every real release and looks exactly
    # like a valid key -- the same "reading that can't tell two cases apart,
    # reported as one of them" failure this whole arc keeps finding. Refuse
    # instead of emitting a key that looks fine.
    if ! is_valid_tag "$tag"; then
      echo "version.sh: cannot sort '$tag' -- not a well-formed <upstream>-cove.<n> tag. Refusing to emit a key that would look valid." >&2
      exit 1
    fi
    base="${tag%-cove.*}"
    n="${tag##*-cove.}"
    # Zero-pad the counter so plain string sort matches numeric sort
    # (cove.10 must sort after cove.9).
    printf '%s-cove.%010d\n' "$base" "$n"
    ;;

  --next)
    # --exclude keeps our own release tags out of the candidate set. Without
    # it, once any -cove.* tag exists, `--match`'s glob (which cannot express
    # "digits only" -- `[0-9]*` is one digit then ANY characters, not
    # "one-or-more digits") also matches "v0.28.6-cove.9", and once a cove
    # tag is closer to HEAD than the real upstream tag, describe returns the
    # cove tag itself as "base" -- corrupting every version after the first
    # release (verified: v0.28.6, v0.28.6-cove.1 on a later commit, HEAD at
    # that commit -- describe with --match alone returns "v0.28.6-cove.1").
    base=$(git describe --tags --abbrev=0 \
             --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude '*-cove.*' 2>/dev/null)
    if [ -z "$base" ]; then
      echo "version.sh: FATAL -- no upstream vX.Y.Z tag reachable from HEAD; cannot compute a base version." >&2
      exit 95
    fi

    # Positive evidence the local tag set is trustworthy, before an empty
    # search for OUR tags is allowed to mean "no releases yet". A shallow
    # clone (or one whose depth cannot even be determined) can still resolve
    # $base above -- git only needs the one nearest matching tag for that --
    # while missing every other tag in the repository, including real cove
    # releases. The workflow sets fetch-depth: 0 and fetch-tags: true today;
    # that makes this check pass today, not unnecessary to have.
    shallow=$(git rev-parse --is-shallow-repository 2>/dev/null)
    if [ "$shallow" != "false" ]; then
      echo "version.sh: FATAL -- refusing to trust an empty release search: this clone is shallow (or its depth could not be determined), which looks identical to \"no releases yet\" but can hide real ones. Fetch full history and tags (fetch-depth: 0, fetch-tags: true) and retry." >&2
      exit 96
    fi

    last=0
    while IFS= read -r t; do
      [ -z "$t" ] && continue
      is_valid_tag "$t" || continue
      n="${t##*-cove.}"
      [ "$n" -gt "$last" ] && last="$n"
    done < <(git tag --list "${base}-cove.*")

    echo "${base}-cove.$((last + 1))"
    ;;

  *)
    echo "version.sh: FATAL -- $USAGE (subcommand missing or unrecognised). Refusing to run." >&2
    exit 93
    ;;
esac
