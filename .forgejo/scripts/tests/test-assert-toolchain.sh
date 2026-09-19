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

# The assertion asks rustup TWO unrelated questions -- which toolchain is
# active, and which components it has -- so the stub has to answer them
# separately. make_stub echoes one string whatever the arguments, which would
# make a test that changes the active toolchain silently also empty the
# component list: the failure would then have two causes and the suite could
# not say which it had proven. Every rustup stub below goes through here.
#
# HEALTHY_COMPONENTS is the real output shape, copied from
# `rustup component list --installed` on the pinned nightly (2026-09-19),
# triple suffixes and all -- a stub printing bare `clippy` would pass an
# assertion that matched only bare names and prove nothing about the image.
HEALTHY_COMPONENTS="cargo-x86_64-unknown-linux-gnu
clippy-x86_64-unknown-linux-gnu
llvm-tools-x86_64-unknown-linux-gnu
rust-std-x86_64-unknown-linux-gnu
rustc-x86_64-unknown-linux-gnu
rustfmt-x86_64-unknown-linux-gnu"

# rustup_stub <active-toolchain-line> [component-list-text]
rustup_stub() {
  local active="$1"; local comps="${2-$HEALTHY_COMPONENTS}"
  { echo '#!/usr/bin/env bash'
    echo 'if [ "${1:-}" = "component" ]; then'
    printf '  cat <<%s\n%s\n%s\n' "'COMPS_EOF'" "$comps" "COMPS_EOF"
    echo '  exit 0'
    echo 'fi'
    printf 'echo %q\n' "$active"
    echo 'exit 0'
  } > "$BIN/rustup"
  chmod +x "$BIN/rustup"
}

healthy() {
  rustup_stub "${PIN}-x86_64-unknown-linux-gnu (overridden by '$WORK/rust-toolchain.toml')"
  make_stub cargo  0 "cargo 1.92.0-nightly (abcdef012 2099-01-01)"
  # sccache is stubbed separately from $TOOLS on purpose: $TOOLS is the set the
  # capped checks DECLARE, and sccache is precisely the tool that is required
  # without being declared. Folding it in would erase the distinction the test
  # below exists to hold open.
  present $TOOLS sccache; python_stub 0
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
# Through rustup_stub, so the component list stays healthy and the ONLY
# difference from the passing case is the active toolchain. A make_stub here
# would also blank the components, and the rc=1 below would no longer be
# evidence that a wrong toolchain is caught.
rustup_stub "stable-x86_64-unknown-linux-gnu (default)"
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
rustup_stub "nightly-2099-01-03-x86_64-unknown-linux-gnu (overridden)"
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

echo "== the tool that is required without being declared: sccache =="
# sccache reaches a capped check as RUSTC_WRAPPER, never as a command, so no
# `tools:` list names it and the run-time gate cannot refuse 97 for it. If the
# image lacks it, every compiling capped check fails in the ORDINARY range the
# moment the cache is configured. The assertion is the only place that can
# catch it, so prove the assertion actually does.
healthy; absent sccache; run
[ "$rc" -eq 1 ] && ok "sccache missing fails the build (1)" \
  || bad "a missing sccache was accepted, got rc=$rc: $out"
grep -q "sccache is NOT in this image" <<<"$out" \
  && ok "and names it, rather than failing anonymously" \
  || bad "sccache absence was not named: $out"
grep -q "ORDINARY range" <<<"$out" \
  && ok "and says what would happen instead, in the build log" \
  || bad "does not explain the consequence: $out"

# THE DRIFT GUARD, and the reason it reads cache-env.sh rather than asserting
# the string "sccache". The wrapper's name is DECIDED in cache-env.sh; the
# assertion only has to agree with it. Hard-coding "sccache" in both places
# would recreate exactly the defect this whole block is about — two
# hand-maintained copies with nothing keeping them in step — and a switch to
# some other wrapper would leave the assertion cheerfully requiring a program
# nothing sets any more.
CACHE_ENV="$HERE/../cache-env.sh"
if [ ! -f "$CACHE_ENV" ]; then
  bad "no cache-env.sh at $CACHE_ENV -- the wrapper requirement is unverified"
else
  WRAPPER=$(sed -n 's/.*RUSTC_WRAPPER=\([A-Za-z0-9_-]*\).*/\1/p' "$CACHE_ENV" | head -1)
  if [ -z "$WRAPPER" ]; then
    bad "could not find what cache-env.sh sets RUSTC_WRAPPER to -- this comparison checked nothing"
  else
    ok "cache-env.sh sets RUSTC_WRAPPER=$WRAPPER"
    # Derived, not assumed: whatever that program is, the assertion must
    # require it. Proven by REMOVING it and requiring a named failure -- a
    # grep for the name in the script would pass on a script that merely
    # mentioned it in a comment.
    healthy; absent "$WRAPPER"; run
    [ "$rc" -eq 1 ] && grep -q "$WRAPPER" <<<"$out" \
      && ok "and the assertion refuses an image without $WRAPPER, by name" \
      || bad "cache-env.sh forwards $WRAPPER but the assertion does not require it: rc=$rc $out"
  fi
fi

# And the forwarding half of the claim: run-check.sh must actually carry
# RUSTC_WRAPPER across the cap boundary, or none of the above matters.
RUN_CHECK="$HERE/../run-check.sh"
if [ ! -f "$RUN_CHECK" ]; then
  bad "no run-check.sh at $RUN_CHECK -- cannot confirm the variable crosses the cap"
elif grep -v '^[[:space:]]*#' "$RUN_CHECK" | grep -q "RUSTC_WRAPPER"; then
  # Comments stripped first: run-check.sh DISCUSSES the cap boundary at length
  # around this code, so a plain grep would pass on a file that had kept the
  # prose and dropped the variable -- the same "matched the explanation, not
  # the behaviour" defect this suite keeps finding elsewhere.
  ok "run-check.sh forwards RUSTC_WRAPPER into the capped container (in code, not a comment)"
else
  bad "run-check.sh no longer forwards RUSTC_WRAPPER in code; the sccache requirement above may be stale"
fi

echo "== the requirements that are not programs at all: rustup components =="
# clippy and llvm-tools are components of the pinned toolchain, not PATH
# entries. derive-tools.py sees `just` and `cargo` in the commands and can
# never derive them; no tools: list can name them; TOOLCHAIN_REQUIRED_TOOLS
# lists binaries, and cargo-cranky/cargo-llvm-cov being present says nothing
# about the components they drive. The assertion is the only guard that can
# see them, so prove it does -- by removing each one and requiring a NAMED
# failure, never by grepping the script for the word.
for comp in clippy llvm-tools; do
  healthy
  rustup_stub "${PIN}-x86_64-unknown-linux-gnu (overridden)" \
    "$(printf '%s\n' "$HEALTHY_COMPONENTS" | grep -v "^${comp}-")"
  run
  [ "$rc" -eq 1 ] && ok "rustup component $comp missing fails the build (1)" \
    || bad "a missing $comp component was accepted, got rc=$rc: $out"
  grep -q "rustup component $comp is NOT installed" <<<"$out" \
    && ok "and names $comp, rather than failing anonymously" \
    || bad "$comp absence was not named: $out"
  grep -q "ORDINARY range" <<<"$out" \
    && ok "and says what would happen instead" \
    || bad "does not explain the consequence for $comp: $out"
done

# THE CONTROL for the two cases above. Without it they would also be satisfied
# by an assertion that refused every component list it was given -- which would
# refuse the real image.
healthy; run
[ "$rc" -eq 0 ] && ok "and a healthy component list still passes (the control)" \
  || bad "the healthy component list was refused, so the two failures above prove nothing: $out"

# THE ALIAS. Measured 2026-09-19 on the real pinned nightly: the Dockerfile
# installs `--component llvm-tools-preview` and rustup reports it as
# `llvm-tools-<triple>`. Both spellings mean the component is there, so an
# assertion keyed to either literal alone is wrong half the time. This is the
# direction that would fail on a HEALTHY image, which is the worse of the two.
healthy
rustup_stub "${PIN}-x86_64-unknown-linux-gnu (overridden)" \
  "$(printf '%s\n' "$HEALTHY_COMPONENTS" | sed 's/^llvm-tools-/llvm-tools-preview-/')"
run
[ "$rc" -eq 0 ] && ok "the -preview spelling of llvm-tools is accepted too" \
  || bad "an image reporting llvm-tools-preview was refused; the alias is not handled: $out"

# rustup ANSWERING NOTHING must not read as "no components missing". An empty
# list is the shape a broken stub, a changed subcommand or a future rustup
# would produce, and it is exactly the "a sweep that sees less reports less"
# failure: it would sail through as green.
healthy
rustup_stub "${PIN}-x86_64-unknown-linux-gnu (overridden)" ""
run
[ "$rc" -eq 1 ] && ok "an EMPTY component list is refused, not read as clean" \
  || bad "an empty component list passed, so this check can report success without looking: $out"

# THE DRIFT GUARD, derived rather than hand-copied -- the same design as the
# cache-env.sh derivation above, and for the same reason. The components are
# DECIDED in the Dockerfile; the assertion only has to agree with it. Two
# hand-maintained lists with nothing keeping them in step is the defect this
# whole arc is about, and adding a third copy here would recreate it.
DOCKERFILE="$HERE/../../images/ci-toolchain/Dockerfile"
if [ ! -f "$DOCKERFILE" ]; then
  bad "no Dockerfile at $DOCKERFILE -- the component requirements are unverified"
else
  # `-preview` stripped because that is the spelling rustup ACCEPTS on the way
  # in while reporting the canonical name on the way out (measured above).
  WANT=$(grep -oE -- '--component[= ][A-Za-z0-9_-]+' "$DOCKERFILE" \
         | sed -E 's/^--component[= ]//; s/-preview$//' | sort -u)
  if [ -z "$WANT" ]; then
    bad "no --component flags found in $DOCKERFILE -- this comparison checked nothing"
  else
    ok "Dockerfile installs components: $(echo $WANT)"
    for comp in $WANT; do
      healthy
      rustup_stub "${PIN}-x86_64-unknown-linux-gnu (overridden)" \
        "$(printf '%s\n' "$HEALTHY_COMPONENTS" | grep -v "^${comp}-")"
      run
      [ "$rc" -eq 1 ] && grep -q "$comp" <<<"$out" \
        && ok "and the assertion refuses an image without $comp, by name" \
        || bad "the Dockerfile installs $comp but the assertion does not require it: rc=$rc $out"
    done
  fi
fi

echo "== the assertion's tool list against the checks it is protecting =="
# The default list inside assert-toolchain.sh is a hand-copied duplicate of
# what the capped checks declare in checks.yaml, and a duplicate with nothing
# keeping it in step is the defect this whole arc is about. Adding a tool to a
# capped check without adding it here would produce an image that passes its
# own assertion and then refuses 97 in CI — a full queue cycle and a human read
# to discover something this comparison finds for free.
#
# `cargo` is excluded on both sides: it comes from the toolchain itself and is
# asserted separately, by actually running it.
CHECKS="$HERE/../../checks.yaml"
if [ ! -f "$CHECKS" ]; then
  bad "no checks.yaml at $CHECKS -- the list below is unverified"
else
  cmp_out=$(python3 - "$CHECKS" "$SCRIPT" <<'PY'
import sys, re, yaml
checks, script = sys.argv[1], sys.argv[2]
need = set()
for c in yaml.safe_load(open(checks))["checks"]:
    if c.get("compiles") is True:
        need.update(c.get("tools", []))
need.discard("cargo")
m = re.search(r"TOOLCHAIN_REQUIRED_TOOLS:-([^}]*)\}", open(script).read())
if not m:
    print("NOANCHOR"); raise SystemExit(0)
have = set(m.group(1).split())
print("MISSING " + " ".join(sorted(need - have)) if need - have else "", end="")
print(" EXTRA " + " ".join(sorted(have - need)) if have - need else "", end="")
print(" OK" if need == have else "")
PY
)
  case "$cmp_out" in
    NOANCHOR) bad "could not find TOOLCHAIN_REQUIRED_TOOLS in $SCRIPT -- this comparison silently checked nothing" ;;
    *OK*)     ok "every tool the capped checks declare is required by the assertion, and no others" ;;
    *)        bad "assertion tool list and checks.yaml disagree:$cmp_out" ;;
  esac
fi

[ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
