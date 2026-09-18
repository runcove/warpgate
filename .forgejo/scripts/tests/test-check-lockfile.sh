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
EMPTY_REPO="${TMPDIR:-/tmp}/check-lockfile-test-empty.$$"
mkdir -p "$EMPTY_REPO"
out=$(cd "$EMPTY_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok "zero lockfiles: refuses, does not pass" \
  || bad "zero lockfiles: exited 0 with nothing examined: $out"
grep -qi "zero package-lock" <<<"$out" && ok "zero lockfiles: says why" \
  || bad "zero lockfiles: silent about examining nothing: $out"
rm -rf "$EMPTY_REPO"

# --- Sanity: a healthy lockfile still passes --------------------------------
# Proves the fix is not just strict -- a checker that always refuses would
# also "pass" both cases above.
GOOD_REPO="${TMPDIR:-/tmp}/check-lockfile-test-good.$$"
mkdir -p "$GOOD_REPO"
cat > "$GOOD_REPO/package-lock.json" <<'EOF'
{"packages": {"": {}, "node_modules/x": {"resolved": "https://x", "integrity": "sha512-x"}}}
EOF
out=$(cd "$GOOD_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "a healthy lockfile still passes" \
  || bad "a healthy lockfile no longer passes (rc=$rc): $out"
rm -rf "$GOOD_REPO"

# --- Sanity: a lockfile with a real problem is still caught -----------------
BAD_REPO="${TMPDIR:-/tmp}/check-lockfile-test-bad.$$"
mkdir -p "$BAD_REPO"
cat > "$BAD_REPO/package-lock.json" <<'EOF'
{"packages": {"": {}, "node_modules/x": {"resolved": "", "integrity": ""}}}
EOF
out=$(cd "$BAD_REPO" && "$SCRIPT" 2>&1); rc=$?
[ "$rc" -ne 0 ] && ok "a lockfile missing resolved/integrity still fails" \
  || bad "a real problem was not caught (rc=$rc): $out"
grep -q "missing resolved or integrity" <<<"$out" \
  && ok "names the problem" || bad "did not name the problem: $out"
rm -rf "$BAD_REPO"

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
