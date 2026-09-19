#!/usr/bin/env bash
# assert-toolchain.sh is the one thing standing between "this image is wrong"
# and five capped checks going red in the ordinary range, where nothing
# distinguishes our mistake from upstream's verdict on our code. So it has to
# be shown to FAIL, not just to pass on a healthy image.
#
# Everything here runs against stub `rustup`, `cargo` and tool binaries on a
# private PATH. No Rust toolchain is installed on the machine this was written
# on and none is downloaded: the script's whole job is reading what those two
# commands say, so stubbing them exercises exactly the logic under test. What
# it cannot prove is that a REAL rustup says what these stubs say — that is
# what the assertion running inside the actual image build is for.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${ASSERT_TOOLCHAIN:-$HERE/../../images/ci-toolchain/assert-toolchain.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

[ -f "$SCRIPT" ] || { echo "  FAIL  $SCRIPT not found"; exit 1; }

# A DELIBERATELY FICTIONAL pin, not the repo's real one. Two reasons: nothing
# here should read like a third copy of a value whose source of truth is
# rust-toolchain.toml, and using a date the script could not possibly know
# proves it hard-codes the real pin nowhere — a suite written with the real
# string would pass just as happily on a script that ignored its argument.
PIN="nightly-2099-01-02"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"
# Real bash/grep/command etc. still need to work: this is a PATH built from
# links to what the script itself uses, never an empty PATH, which would break
# bash's own execution and prove nothing (the lesson from test-check-lockfile).
for b in bash grep sed cat env dirname basename mktemp rm ls; do
  p=$(command -v "$b" 2>/dev/null) && ln -sf "$p" "$BIN/$b"
done

# make_stub <name> <exit> <output...>
make_stub() {
  local n="$1"; local rc="$2"; shift 2
  { echo '#!/usr/bin/env bash'; printf 'echo %q\n' "$*"; echo "exit $rc"; } > "$BIN/$n"
  chmod +x "$BIN/$n"
}
present() { for n in "$@"; do printf '#!/usr/bin/env bash\nexit 0\n' > "$BIN/$n"; chmod +x "$BIN/$n"; done; }
absent()  { for n in "$@"; do rm -f "$BIN/$n"; done; }

TOOLS="just git tar python3 npm oasdiff cargo-cranky cargo-llvm-cov cargo-cyclonedx"

# python3 is special: the script both runs it as a tool and asks it to import
# yaml. One stub covers both, and a second one fails only the import, so
# "python3 present" and "PyYAML importable" stay distinguishable.
python_stub() { # python_stub <yaml-ok:0|1>
  { echo '#!/usr/bin/env bash'
    echo 'if [ "${1:-}" = "-c" ]; then'
    echo "  case \"\${2:-}\" in *yaml*) exit $1 ;; esac"
    echo 'fi'
    echo 'exit 0'; } > "$BIN/python3"
  chmod +x "$BIN/python3"
}

WORK="$TMP/src"; mkdir -p "$WORK"
printf '[toolchain]\nchannel = "%s"\n' "$PIN" > "$WORK/rust-toolchain.toml"

healthy() {
  make_stub rustup 0 "${PIN}-x86_64-unknown-linux-gnu (overridden by '$WORK/rust-toolchain.toml')"
  make_stub cargo  0 "cargo 1.92.0-nightly (abcdef012 2099-01-01)"
  present $TOOLS; python_stub 0
}
run() { out=$(PATH="$BIN" bash "$SCRIPT" "$PIN" "$WORK" 2>&1); rc=$?; }

echo "== the healthy image passes, and says what it checked =="
healthy; run
[ "$rc" -eq 0 ] && ok "a correct image passes (0)" || bad "healthy image should pass, got rc=$rc: $out"
grep -q "active toolchain in .* is $PIN" <<<"$out" && ok "and names the toolchain it found" \
  || bad "does not report the active toolchain: $out"
n=$(grep -c "^  ok    " <<<"$out")
[ "$n" -ge 12 ] && ok "and reports $n individual checks, not one summary verdict" \
  || bad "expected at least 12 ok lines, got $n: $out"

echo "== the case this exists for: a different toolchain =="
healthy
make_stub rustup 0 "stable-x86_64-unknown-linux-gnu (default)"
run
[ "$rc" -eq 1 ] && ok "a stable toolchain fails the build (1)" || bad "wrong toolchain should fail, got rc=$rc: $out"
grep -q "expected: $PIN" <<<"$out" && grep -q "actual:   stable" <<<"$out" \
  && ok "and prints expected and actual against each other" \
  || bad "mismatch does not show both values: $out"
grep -q "look like a verdict on our code" <<<"$out" \
  && ok "and says why that matters, in the build log where someone will read it" \
  || bad "mismatch message does not explain the consequence: $out"

# A near miss, not a different channel: the same nightly one day off. A
# prefix/substring assertion written loosely would wave this through.
healthy
make_stub rustup 0 "nightly-2099-01-03-x86_64-unknown-linux-gnu (overridden)"
run
[ "$rc" -eq 1 ] && ok "a nightly one day off the pin also fails" \
  || bad "a nightly one day off the pin was accepted as $PIN, got rc=$rc: $out"

echo "== rustup failing is not the same as rustup disagreeing =="
healthy
make_stub rustup 1 "error: toolchain '$PIN' is not installed"
run
[ "$rc" -eq 1 ] && ok "rustup failing fails the build (1)" || bad "expected 1, got rc=$rc: $out"
grep -q "could not report an active toolchain" <<<"$out" \
  && ok "and is reported as ABSENT, not as a mismatch" \
  || bad "a rustup failure was reported as something else: $out"
grep -q "actual:" <<<"$out" \
  && bad "a rustup failure printed a mismatch message; the two cases share a voice: $out" \
  || ok "and never prints the mismatch message, so the log says which happened"

echo "== the vacuity guard =="
# The assertion asks what toolchain is active FOR A DIRECTORY. Without the pin
# file it would describe the image default and agree with itself.
healthy
NOTOML="$TMP/empty"; mkdir -p "$NOTOML"
out=$(PATH="$BIN" bash "$SCRIPT" "$PIN" "$NOTOML" 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "no rust-toolchain.toml: REFUSES (2) rather than passing" \
  || bad "a missing pin file should refuse with 2, got rc=$rc: $out"
grep -q "Nothing was checked" <<<"$out" \
  && ok "and says nothing was checked, rather than reporting a verdict" \
  || bad "refusal does not disclaim its own result: $out"

# The pin file present but naming a DIFFERENT toolchain than the build expects:
# the assertions would then be testing a pin nobody asked for.
healthy
STALE="$TMP/stale"; mkdir -p "$STALE"
printf '[toolchain]\nchannel = "nightly-2099-06-06"\n' > "$STALE/rust-toolchain.toml"
out=$(PATH="$BIN" bash "$SCRIPT" "$PIN" "$STALE" 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "pin file naming another toolchain: REFUSES (2)" \
  || bad "a stale expectation should refuse with 2, got rc=$rc: $out"

out=$(PATH="$BIN" bash "$SCRIPT" "" "$WORK" 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "no expected toolchain given: REFUSES (2), asserts nothing silently" \
  || bad "an empty expectation should refuse with 2, got rc=$rc: $out"

echo "== cargo must RUN, not merely be wanted =="
# rustup can answer from the pin file while the toolchain is unusable.
healthy
make_stub cargo 1 "error: toolchain '$PIN' is not installed"
run
[ "$rc" -eq 1 ] && ok "cargo failing fails the build even when rustup agrees" \
  || bad "expected 1, got rc=$rc: $out"
grep -q "cargo does not run" <<<"$out" && ok "and says so in its own words" \
  || bad "cargo failure not reported distinctly: $out"

healthy
make_stub cargo 0 "cargo 1.90.0 (stable 2026-06-01)"
run
[ "$rc" -eq 1 ] && ok "a cargo that runs but is not nightly fails" \
  || bad "a stable cargo was accepted, got rc=$rc: $out"

echo "== every declared tool, and PyYAML which the tools gate cannot see =="
for missing in just git tar npm oasdiff cargo-cranky cargo-llvm-cov cargo-cyclonedx; do
  healthy; absent "$missing"; run
  if [ "$rc" -eq 1 ] && grep -q "$missing is declared by a capped check" <<<"$out"; then continue; fi
  bad "$missing missing: expected a failure naming it, got rc=$rc: $out"
done
[ "$fails" -eq 0 ] && ok "each of the 8 declared tools is individually required and named when absent"

healthy; python_stub 1; run
[ "$rc" -eq 1 ] && grep -q "cannot import yaml" <<<"$out" \
  && ok "PyYAML missing fails, though python3 itself is present" \
  || bad "PyYAML absence was not caught, or was confused with python3 itself: rc=$rc $out"

[ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
