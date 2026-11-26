#!/bin/bash
# test-release-notes-tag-message.sh -- tests release-notes-tag-message.sh in throwaway git repositories.
# Run: bash .github/cove-ci/test-release-notes-tag-message.sh      Exit: 0 all pass, 1 a failure.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SCRIPT="$HERE/release-notes-tag-message.sh"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rntm.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
REPO="$WORK/repo"
git init -q "$REPO"
cd "$REPO" || exit 1
git commit -q --allow-empty -m "the commit message must never be published"
COMMIT=$(git rev-parse HEAD)

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; [ $# -lt 2 ] || printf '%s\n' "$2" | sed 's/^/     /'; }

# raw_tag NAME BODY: an annotated tag whose message is exactly BODY (so a signature block can be
# written verbatim, without a key).
raw_tag() {
  local oid
  oid=$({
    printf 'object %s\ntype commit\ntag %s\ntagger t <t@example.invalid> 1700000000 +0000\n\n' "$COMMIT" "$1"
    printf '%s' "$2"
  } | git hash-object -t tag -w --stdin)
  git update-ref "refs/tags/$1" "$oid"
}

# run_case NAME EXPECTED: stdout of the script for TAG=NAME must be exactly EXPECTED (and exit 0).
run_case() {
  local name=$1 want=$2 got rc=0
  got=$(TAG="$name" bash "$SCRIPT" 2>"$WORK/err"; echo "rc=$?")
  [ "$got" = "${want}${want:+$'\n'}rc=0" ] || rc=1
  if [ $rc -eq 0 ]; then ok "$name"; else bad "$name" "want: [$want]  got: [$got]  stderr: $(cat "$WORK/err")"; fi
}

# 1. an annotated tag with a message: subject and body, as written.
git tag -a -m "advisory: the kernel needs a reboot" -m "second paragraph" v1-cove.1 "$COMMIT"
run_case v1-cove.1 $'advisory: the kernel needs a reboot\n\nsecond paragraph'

# 2. a PGP-signed tag: the signature block is gone, the message stays.
raw_tag v2-cove.1 $'release notes line\n\nmore\n-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEEfake\n=abcd\n-----END PGP SIGNATURE-----\n'
run_case v2-cove.1 $'release notes line\n\nmore'

# 3. an SSH-signed tag.
raw_tag v3-cove.1 $'ssh signed\n-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQfake\n-----END SSH SIGNATURE-----\n'
run_case v3-cove.1 'ssh signed'

# 4. a lightweight tag: nothing (never the commit's message).
git tag v4-cove.1 "$COMMIT"
run_case v4-cove.1 ''

# 5. an annotated tag with no message, and one with only a signature block: nothing.
raw_tag v5-cove.1 ''
run_case v5-cove.1 ''
raw_tag v5-cove.2 $'\n\n-----BEGIN PGP SIGNATURE-----\n\nfake\n-----END PGP SIGNATURE-----\n'
run_case v5-cove.2 ''

# 6. a tag that is not there: nothing, no error.
run_case v6-cove.1 ''

# 7. hostile text is printed, never run or expanded.
HOSTILE=$'$(touch PWNED) `touch PWNED2` ${TAG} %(contents) \\n \\\\ -n -e *\n$((1+1)) "quoted" \'single\'\n--- not a signature'
raw_tag v7-cove.1 "$HOSTILE"$'\n'
run_case v7-cove.1 "$HOSTILE"
if [ -e PWNED ] || [ -e PWNED2 ]; then bad "v7-cove.1 ran message text"; else ok "v7-cove.1 ran nothing"; fi

# 8. surrounding blank lines go; inner ones stay.
raw_tag v8-cove.1 $'\n\n  first\n\n\nlast\n\n-----BEGIN PGP SIGNATURE-----\nx\n-----END PGP SIGNATURE-----\n'
run_case v8-cove.1 $'  first\n\n\nlast'

# 9. an unterminated signature block removes the rest.
raw_tag v9-cove.1 $'kept\n-----BEGIN PGP SIGNATURE-----\ntruncated\n'
run_case v9-cove.1 'kept'

# 10. a bad TAG is refused (exit 64), nothing printed; so is an unset one.
# shellcheck disable=SC2016  # the $( ) is a literal bad name
for t in 'v1/../x' 'a b' '' '-x$(id)'; do
  out=$(TAG="$t" bash "$SCRIPT" 2>/dev/null); rc=$?
  if [ "$rc" = 64 ] && [ -z "$out" ]; then ok "refused TAG [$t]"; else bad "TAG [$t]: exit $rc, out [$out], want exit 64 and no output"; fi
done
out=$(env -u TAG bash "$SCRIPT" 2>/dev/null); rc=$?
if [ "$rc" = 64 ] && [ -z "$out" ]; then ok "refused unset TAG"; else bad "unset TAG: exit $rc, out [$out]"; fi

# 11. the workflow wires it in: the publish job's notes step calls the script and appends the
# message with printf '%s\n'.
WF="$HERE/../workflows/cove-release.yml"
if grep -q 'wfci/.github/cove-ci/release-notes-tag-message.sh' "$WF"; then ok "workflow calls the script"; else bad "workflow does not call the script"; fi
if grep -q "printf '%s\\\\n' \"\$tag_msg\" >> \"\$RUNNER_TEMP/notes.md\"" "$WF"; then ok "workflow appends with printf"; else bad "workflow does not append with printf '%s\\n'"; fi
if grep -q '::error::could not fetch the tag object' "$WF"; then ok "workflow fails when the tag fetch fails"; else bad "workflow has no ::error:: for a failed tag fetch"; fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
