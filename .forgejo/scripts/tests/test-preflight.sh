#!/usr/bin/env bash
# preflight.sh exists because the first real run died 3 seconds after
# checkout on `ModuleNotFoundError: No module named 'yaml'` -- an ordinary
# exit 1, nowhere in this codebase's 89-99 refusal band, from a job
# container that simply could not run any check at all. Each of the four
# conditions preflight.sh checks is made to fail INDIVIDUALLY here, on an
# isolated PATH built from stub fixtures (never a real broken Python
# install, never a real container runtime), and the exact exit code and the
# message naming the missing thing are asserted -- not `rc -ne 0`, which
# would not have caught the original bug (that was already a nonzero exit;
# the defect was WHICH nonzero).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../preflight.sh"
FIXTURES="$HERE/fixtures/preflight"
REAL_BASH="$(command -v bash)"

BIN="${TMPDIR:-/tmp}/preflight-test-bin.$$"
trap 'rm -rf "$BIN"' EXIT

fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

# Rebuilds $BIN from scratch with only a real bash (so the script's own
# `#!/usr/bin/env bash` shebang still resolves under the restricted PATH we
# are about to hand it) plus whichever fixture stubs the caller names.
fresh_bin() {
  rm -rf "$BIN"
  mkdir -p "$BIN"
  ln -s "$REAL_BASH" "$BIN/bash"
  for pair in "$@"; do
    fixture="${pair%%:*}"
    name="${pair##*:}"
    ln -s "$FIXTURES/$fixture" "$BIN/$name"
  done
}

run() {
  PATH="$BIN" "$SCRIPT" 2>&1
}

# 1. python3 entirely missing from PATH. A working docker stub is included
#    anyway, so a bug that reordered the checks (docker before python3)
#    would still show up as the wrong message here rather than a lucky pass.
fresh_bin docker-ok:docker
out=$(run); rc=$?
[ "$rc" -eq 93 ] && ok "python3 missing: exits 93, not an ordinary failure" \
  || bad "python3 missing: expected rc=93, got rc=$rc: $out"
grep -qi "python3 is not on PATH" <<<"$out" && ok "python3 missing: names python3" \
  || bad "python3 missing: message does not name python3: $out"

# 2. python3 present, but the yaml module is not importable -- the ACTUAL
#    first-run failure, reproduced without touching the real Python install.
fresh_bin python3-no-yaml:python3 docker-ok:docker
out=$(run); rc=$?
[ "$rc" -eq 93 ] && ok "yaml not importable: exits 93, not the bare ModuleNotFoundError exit 1 the first real run hit" \
  || bad "yaml not importable: expected rc=93, got rc=$rc: $out"
grep -qi "yaml" <<<"$out" && ok "yaml not importable: names the yaml module" \
  || bad "yaml not importable: message does not name yaml: $out"

# 3. python3 fine, but the docker CLI is entirely missing from PATH.
fresh_bin python3-ok:python3
out=$(run); rc=$?
[ "$rc" -eq 93 ] && ok "docker CLI missing: exits 93, not an ordinary failure" \
  || bad "docker CLI missing: expected rc=93, got rc=$rc: $out"
grep -qi "docker CLI is not on PATH" <<<"$out" && ok "docker CLI missing: names the docker CLI" \
  || bad "docker CLI missing: message does not name the docker CLI: $out"

# 4. docker CLI present, but the daemon is unreachable (dind not up yet, or
#    an unreachable DOCKER_HOST) -- `docker info` fails.
fresh_bin python3-ok:python3 docker-unreachable:docker
out=$(DOCKER_HOST=tcp://dind:2375 PATH="$BIN" "$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "daemon unreachable: exits 93, not the 91 hardened-run.sh would eventually hit" \
  || bad "daemon unreachable: expected rc=93, got rc=$rc: $out"
grep -qi "daemon is not reachable" <<<"$out" && ok "daemon unreachable: names the daemon" \
  || bad "daemon unreachable: message does not name the daemon: $out"
grep -q "tcp://dind:2375" <<<"$out" && ok "daemon unreachable: message includes the DOCKER_HOST it tried" \
  || bad "daemon unreachable: message omits DOCKER_HOST: $out"

# 5. All four present: preflight must actually pass, not just be strict --
#    a check that always refuses would also "pass" the four cases above.
fresh_bin python3-ok:python3 docker-ok:docker
out=$(run); rc=$?
[ "$rc" -eq 0 ] && ok "all four present: preflight passes" \
  || bad "all four present: expected rc=0, got rc=$rc: $out"
grep -qi "preflight: ok" <<<"$out" && ok "all four present: says so" \
  || bad "all four present: silent about success: $out"

echo
if [ "$fails" -eq 0 ]; then
  echo "test-preflight.sh: PASS"
else
  echo "test-preflight.sh: FAILURES"
fi
exit "$fails"
