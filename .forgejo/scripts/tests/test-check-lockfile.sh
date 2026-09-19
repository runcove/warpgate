#!/usr/bin/env bash
# check-lockfile.sh's own proven false-PASS bug (2026-09-18, Task 7A Step
# 2A): jq missing was silently read as "zero problems found" (its own exit
# status was never checked), and finding zero lockfiles was silently read
# the same way (an empty loop body never sets rc). Both are fixed to refuse
# instead of pass; this proves it, and that a healthy lockfile still passes.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${CHECK_LOCKFILE:-$HERE/../check-lockfile.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

# --- Step 4(d), part 1: jq unavailable refuses instead of passing ----------
# A self-contained PATH built only from stub links to what check-lockfile.sh
# actually needs besides jq (bash for its own shebang, find and sed for its
# own body) -- never a PATH="" or similarly total restriction, which would
# break bash's own execution and produce a 127 from the wrong thing, proving
# nothing. jq is simply left out of this PATH -- not uninstalled anywhere on
# this machine -- so the ONLY tool missing from check-lockfile.sh's point of
# view is jq.
BIN="${TMPDIR:-/tmp}/check-lockfile-test-bin.$$"
mkdir -p "$BIN"
for b in bash find sed; do ln -sf "$(command -v "$b")" "$BIN/$b"; done

REPO_STUB="${TMPDIR:-/tmp}/check-lockfile-test-repo.$$"
mkdir -p "$REPO_STUB"
cat > "$REPO_STUB/package-lock.json" <<'EOF'
{"packages": {"": {}, "node_modules/x": {"resolved": "https://x", "integrity": "sha512-x"}}}
EOF

out=$(cd "$REPO_STUB" && PATH="$BIN" "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "jq missing: refuses (97), does not pass" \
  || bad "jq missing: expected rc=97, got rc=$rc: $out"
grep -qi "jq" <<<"$out" && ok "jq missing: names jq" \
  || bad "jq missing: message does not name jq: $out"
grep -qi "^PASS\|missing resolved or integrity" <<<"$out" \
  && bad "jq missing: still reported as if it had examined something: $out" \
  || ok "jq missing: does not claim to have examined anything"

rm -rf "$BIN" "$REPO_STUB"

# --- Step 4(d), part 2: zero lockfiles found refuses instead of passing ----
# Fix round 1: exits 99 specifically, not the ordinary FAIL (1) it used to.
# "found nothing to examine" is neither a pass nor a fail -- exit 1 would be
# indistinguishable from "ran and found a real problem", which is exactly
# the confusion this whole task exists to remove. rc -ne 0 alone would not
# catch a regression that kept refusing but downgraded it back to 1.
EMPTY_REPO="${TMPDIR:-/tmp}/check-lockfile-test-empty.$$"
mkdir -p "$EMPTY_REPO"
out=$(cd "$EMPTY_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "zero lockfiles: refuses (99), not an ordinary FAIL" \
  || bad "zero lockfiles: expected rc=99, got rc=$rc: $out"
grep -qi "zero package-lock" <<<"$out" && ok "zero lockfiles: says why" \
  || bad "zero lockfiles: silent about examining nothing: $out"
rm -rf "$EMPTY_REPO"

# --- Sanity: a healthy lockfile still passes --------------------------------
# Proves the fix is not just strict -- a checker that always refuses would
# also "pass" both cases above.
#
# These fixtures gained `"lockfileVersion": 3` on 2026-09-19. Not to make a new
# rule pass -- a real package-lock.json always carries the key, so its absence
# here was the fixture being unrealistic, and the rule below refuses a file
# whose format it cannot identify for the same reason it refuses an empty one.
GOOD_REPO="${TMPDIR:-/tmp}/check-lockfile-test-good.$$"
mkdir -p "$GOOD_REPO"
cat > "$GOOD_REPO/package-lock.json" <<'EOF'
{"lockfileVersion": 3,
 "packages": {"": {}, "node_modules/x": {"resolved": "https://x", "integrity": "sha512-x"}}}
EOF
out=$(cd "$GOOD_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "a healthy lockfile still passes" \
  || bad "a healthy lockfile no longer passes (rc=$rc): $out"
# A pass that says nothing is the defect runcove-4h0 is about: run 529's whole
# record of this check was "PASS lockfile", so a run covering both of the
# repo's lockfiles and a run covering one looked the same. The COUNTS, not
# merely some output: "examined 1" must be distinguishable from "examined 2".
grep -q "examined 1 lockfile(s), 1 package entries" <<<"$out" \
  && ok "a pass reports what it examined, with both counts" \
  || bad "a pass does not report its counts: $out"
rm -rf "$GOOD_REPO"

# The other direction, and the one that matters: the count must TRACK. A
# hardcoded "examined 1" would satisfy the assertion above forever.
TWO_REPO="${TMPDIR:-/tmp}/check-lockfile-test-two.$$"
mkdir -p "$TWO_REPO/sub"
cat > "$TWO_REPO/package-lock.json" <<'EOF'
{"lockfileVersion": 3,
 "packages": {"": {}, "node_modules/x": {"resolved": "https://x", "integrity": "sha512-x"}}}
EOF
cat > "$TWO_REPO/sub/package-lock.json" <<'EOF'
{"lockfileVersion": 3,
 "packages": {"": {},
   "node_modules/y": {"resolved": "https://y", "integrity": "sha512-y"},
   "node_modules/z": {"resolved": "https://z", "integrity": "sha512-z"}}}
EOF
out=$(cd "$TWO_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "two healthy lockfiles pass" \
  || bad "two healthy lockfiles did not pass (rc=$rc): $out"
grep -q "examined 2 lockfile(s), 3 package entries" <<<"$out" \
  && ok "the counts track the input, they are not a fixed sentence" \
  || bad "counts did not track (expected 2 files / 3 entries): $out"
rm -rf "$TWO_REPO"

# --- lockfileVersion 1: the false PASS one level in --------------------------
# Version 1 has no `.packages` at all -- its tree lives under `.dependencies`.
# The filter matches nothing, `missing` is empty, and the old code reported
# PASS having verified not one package. Refusal, not a pass: nothing was read.
V1_REPO="${TMPDIR:-/tmp}/check-lockfile-test-v1.$$"
mkdir -p "$V1_REPO"
cat > "$V1_REPO/package-lock.json" <<'EOF'
{"lockfileVersion": 1,
 "dependencies": {"x": {"version": "1.0.0", "resolved": "", "integrity": ""}}}
EOF
out=$(cd "$V1_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "lockfileVersion 1: refuses (99), does not pass vacuously" \
  || bad "lockfileVersion 1: expected rc=99, got rc=$rc: $out"
# Matched on wording unique to the VERSION guard, not on "lockfileVersion 1",
# which both refusals print. Found by mutation 2026-09-19: deleting the version
# guard entirely left this test green, because a v1 file then falls through to
# the zero-entries guard and refuses with 99 for a different reason -- and the
# assertion, asking only whether the version was named, could not tell the two
# apart. A test that cannot distinguish two causes of the same exit code is the
# same defect as the check it is testing, which is the whole subject here.
grep -q "only versions 2 and 3 have" <<<"$out" \
  && ok "lockfileVersion 1: refused for the RIGHT reason, not by falling through" \
  || bad "lockfileVersion 1: refused, but not by the version guard: $out"
# The fixture is deliberately one that WOULD fail if it were readable -- both
# fields empty. So a green result here could never be "it looked and the file
# was fine"; the only way to pass is to have looked at nothing.
grep -q "examined" <<<"$out" \
  && bad "lockfileVersion 1: claimed to have examined something: $out" \
  || ok "lockfileVersion 1: makes no claim about having examined anything"
rm -rf "$V1_REPO"

# --- A lockfile with no entries ---------------------------------------------
# Parses, carries a version this check understands, and still yields nothing:
# truncated, or holding only the root "" entry the filter excludes.
EMPTY_PKGS="${TMPDIR:-/tmp}/check-lockfile-test-emptypkgs.$$"
mkdir -p "$EMPTY_PKGS"
cat > "$EMPTY_PKGS/package-lock.json" <<'EOF'
{"lockfileVersion": 3, "packages": {"": {}}}
EOF
out=$(cd "$EMPTY_PKGS" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "a lockfile with no entries: refuses (99), does not pass" \
  || bad "no entries: expected rc=99, got rc=$rc: $out"
grep -q "no package entries" <<<"$out" && ok "no entries: says so" \
  || bad "no entries: silent about it: $out"
rm -rf "$EMPTY_PKGS"

# --- Sanity: a lockfile with a real problem is still caught -----------------
BAD_REPO="${TMPDIR:-/tmp}/check-lockfile-test-bad.$$"
mkdir -p "$BAD_REPO"
cat > "$BAD_REPO/package-lock.json" <<'EOF'
{"lockfileVersion": 3,
 "packages": {"": {}, "node_modules/x": {"resolved": "", "integrity": ""}}}
EOF
out=$(cd "$BAD_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "a lockfile missing resolved/integrity still fails (1), not refused (99)" \
  || bad "a real problem was not caught as an ordinary FAIL (rc=$rc): $out"
grep -q "missing resolved or integrity" <<<"$out" \
  && ok "names the problem" || bad "did not name the problem: $out"
# A FAIL must report its scope too, or "found a problem" carries no idea of
# how much was looked at to find it.
grep -q "examined 1 lockfile(s), 1 package entries" <<<"$out" \
  && ok "a FAIL reports what it examined as well" \
  || bad "a FAIL does not report its counts: $out"
rm -rf "$BAD_REPO"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
