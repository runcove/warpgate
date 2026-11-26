#!/bin/bash
# release-notes-tag-message.sh -- print the message of the annotated release tag $TAG,
# signature block removed, for the GitHub Release notes (cove-release.yml, publish job).
#
# WHY. The Release is created with a read-only token, so an advisory cannot be added to its
# notes afterwards; the tag's message is where the maintainer puts it before the tag is pushed.
#
# Reads the tag from the local repository (the caller fetches the tag object). The tag name comes
# in the environment, never in the script text. Prints nothing and exits 0 when the tag is
# lightweight (its "message" would be the commit's, which is not ours to publish), is absent, or
# has no message once the signature block is removed. The message is untrusted text: it is only
# ever piped through awk and printed, never evaluated or expanded.
#
# Removed: a block from a -----BEGIN PGP SIGNATURE----- (or PGP MESSAGE, SIGNED MESSAGE, SSH
# SIGNATURE) line through its -----END ...----- line, or to the end if it never ends; and blank
# lines at the start and end of what is left.
#
# Usage: TAG=v0.30.2-cove.1 release-notes-tag-message.sh      Exit: 0, or 64 for a bad TAG.
# Test: test-release-notes-tag-message.sh (beside this file).
set -euo pipefail

case "${TAG:-}" in
  *[!A-Za-z0-9._-]*|'') echo "REFUSING: TAG '${TAG:-}' is not a plain tag name." >&2; exit 64 ;;
esac

ref="refs/tags/$TAG"
[ "$(git cat-file -t "$ref" 2>/dev/null || true)" = tag ] || exit 0

git for-each-ref --format='%(contents)' "$ref" | awk '
  /^-----BEGIN (PGP SIGNATURE|PGP MESSAGE|SIGNED MESSAGE|SSH SIGNATURE)-----$/ { skip = 1; next }
  skip { if ($0 ~ /^-----END (PGP SIGNATURE|PGP MESSAGE|SIGNED MESSAGE|SSH SIGNATURE)-----$/) skip = 0; next }
  { line[++n] = $0 }
  END {
    a = 1
    while (a <= n && line[a] ~ /^[ \t\r]*$/) a++
    while (n >= a && line[n] ~ /^[ \t\r]*$/) n--
    for (i = a; i <= n; i++) print line[i]
  }'
