#!/usr/bin/env bash
# Runs INSIDE the CI toolchain image, at build time, and fails the build if the
# image is not what it claims to be.
#
# WHY A BUILD-TIME ASSERTION AND NOT A RUN-TIME ONE. Five capped checks are
# about to stop refusing and start running. Until now every one of them refused
# with 97 and said which tool was missing — honest, and impossible to
# misread. The moment this image exists they produce ORDINARY exit codes, and
# no ordinary exit code distinguishes "upstream's verdict on our code" from
# "our image is subtly wrong". That is the single largest risk in this arc, and
# the only cheap place to cut it is here, before the image is ever tagged.
#
# THE CASE THIS EXISTS FOR, specifically. The workspace pins a dated nightly in
# rust-toolchain.toml — that file is the source of truth, and the expected
# value is passed in rather than written here so this script holds no second
# copy to go stale. An image carrying any other
# toolchain does not fail loudly: rustup will happily DOWNLOAD the pinned one
# on first use if it can reach the network, so the image would work, slowly,
# once per container, and an image carrying a stable toolchain would instead
# fail every cargo invocation in the ordinary range — five checks going red
# with nothing to say they went red for our reason and not upstream's.
#
# THE VACUITY GUARD IS THE PART TO REVIEW. `rustup show active-toolchain`
# answers a question ABOUT A DIRECTORY. Run somewhere without a
# rust-toolchain.toml it reports the image default and agrees with itself, so
# an assertion that forgot the file would pass on an image where the pin does
# not resolve at all. This script therefore refuses to render a verdict unless
# it can see the toolchain file it is supposedly testing — the same shape as a
# mutation harness whose mutant never reached the code under test.
set -uo pipefail

EXPECTED="${1:-${EXPECTED_TOOLCHAIN:-}}"
WORKDIR="${2:-${TOOLCHAIN_WORKDIR:-$PWD}}"

fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }
refuse() { echo "assert-toolchain: REFUSE -- $1" >&2; exit 2; }

[ -n "$EXPECTED" ] || refuse "no expected toolchain given; this script would otherwise assert nothing"
[ -d "$WORKDIR" ]  || refuse "workdir $WORKDIR does not exist"

# --- the vacuity guard, before anything else --------------------------------
TOML="$WORKDIR/rust-toolchain.toml"
[ -f "$TOML" ] || refuse "no rust-toolchain.toml at $TOML. Every assertion below asks what
toolchain is active FOR THIS DIRECTORY; without the pin file they would describe the image
default instead and pass on an image where the pin does not resolve at all. Nothing was checked."

grep -q "$EXPECTED" "$TOML" \
  || refuse "$TOML does not name $EXPECTED. Either the pin moved and this build's expectation
is stale, or the wrong file was copied in. Both make the assertions below meaningless."
ok "rust-toolchain.toml is present and names $EXPECTED"

# --- the toolchain actually in force in that directory ----------------------
active=$(cd "$WORKDIR" && rustup show active-toolchain 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  # Distinct from a mismatch on purpose: this is rustup failing (not installed,
  # or the pinned toolchain absent and downloads blocked, which is exactly what
  # the Dockerfile arranges). A mismatch and a failure must never share a
  # message, or the build log cannot say which happened.
  bad "rustup could not report an active toolchain in $WORKDIR (exit $rc). If downloads are
        blocked, this is the pinned toolchain being ABSENT from the image: $active"
else
  case "$active" in
    "$EXPECTED"*) ok "active toolchain in $WORKDIR is $EXPECTED" ;;
    *) bad "active toolchain is NOT the pinned one.
        expected: $EXPECTED
        actual:   $active
        A cargo run in this image would be compiling with the wrong compiler, and every
        resulting failure would look like a verdict on our code." ;;
  esac
fi

# `rustup show active-toolchain` can answer from the pin file without the
# toolchain being usable, so run the compiler itself. This is the difference
# between "the image knows which toolchain it wants" and "the image has it".
ver=$(cd "$WORKDIR" && cargo --version 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  bad "cargo does not run in $WORKDIR (exit $rc): $ver"
elif [[ "$ver" != *-nightly* ]]; then
  bad "cargo runs but is not a nightly build, so the pin is not in force: $ver"
else
  ok "cargo runs under the pin: $ver"
fi

# --- the tools the capped checks declare ------------------------------------
# Taken from the `tools:` lists of the five capped checks in .forgejo/checks.yaml.
# A tool named there and absent here would refuse at run time with 97, which is
# safe but costs a full queue cycle and a human read to discover; finding it at
# image build time costs nothing.
for t in ${TOOLCHAIN_REQUIRED_TOOLS:-just git tar python3 npm oasdiff cargo-cranky cargo-llvm-cov cargo-cyclonedx}; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t present"
  else bad "$t is declared by a capped check and is NOT in this image"; fi
done

# --- the four requirements no `tools:` list can express ----------------------
# Both of these are needed by a capped check and named in no check's tools
# list, for the same underlying reason: the tools gate can only see PATH
# entries that a check's COMMAND invokes. Anything a check needs by another
# route is structurally invisible to it, so it has to be asserted here by
# hand — and said out loud, because a hand-maintained requirement with nothing
# keeping it honest is how the sccache case below went unnoticed in the first
# place.

# PyYAML is not a PATH entry at all.
# check-schema-compat.sh imports checks_lib, which imports yaml.
if python3 -c "import yaml" >/dev/null 2>&1; then ok "python3 can import yaml (PyYAML)"
else bad "python3 cannot import yaml; check-schema-compat.sh would refuse 93 reading its own baseline"; fi

# sccache IS a PATH entry, but it arrives by ENVIRONMENT, not by a command.
# cache-env.sh sets RUSTC_WRAPPER=sccache and run-check.sh forwards
# RUSTC_WRAPPER across the cap boundary, so from the moment the cache is
# configured every compiling capped check invokes it — via cargo, never by
# name. No `tools:` list mentions it, this list did not either, and the drift
# test compares those two lists to EACH OTHER, so all three agreed and the
# agreement read as green. tests/test-assert-toolchain.sh now derives the
# wrapper's name from cache-env.sh rather than trusting the spelling here.
if command -v sccache >/dev/null 2>&1; then ok "sccache present (RUSTC_WRAPPER's program, forwarded into this image by run-check.sh)"
else bad "sccache is NOT in this image. It is named in no tools: list because it arrives
        as RUSTC_WRAPPER, so the run-time tools gate cannot refuse 97 for it: instead every
        compiling capped check would fail in the ORDINARY range the moment the cache is
        configured, and read as a verdict on our code."; fi

# RUSTUP COMPONENTS are not PATH entries and not programs any command names.
# `just clippy` runs `cargo cranky --workspace --all-features`, which is a
# clippy wrapper; `cargo llvm-cov test` needs the llvm-tools profiling
# binaries. Both arrive as components OF THE PINNED TOOLCHAIN, installed on
# Dockerfile line 106.
#
# WHY EVERY EXISTING GUARD IS BLIND TO THEM, which is the whole reason this
# block exists. derive-tools.py reads a check's command and sees `just` and
# `cargo`; a component has no command position to be found in. The `tools:`
# lists therefore cannot name them, so the run-time gate cannot refuse 97 for
# them. And TOOLCHAIN_REQUIRED_TOOLS above lists BINARIES: cargo-cranky being
# present does not imply the clippy component, and cargo-llvm-cov being
# present does not imply llvm-tools. Drop either `--component` from the
# Dockerfile and this image builds, passes its own assertion, and then fails
# `clippy` and `unit-tests` in the ORDINARY range — indistinguishable from
# upstream's verdict on our code. Same shape as sccache above, one layer down.
#
# SPELLING, measured 2026-09-19 against the real pinned nightly: the Dockerfile
# asks for `llvm-tools-preview` and rustup reports it installed as
# `llvm-tools-<triple>`. `-preview` is a live alias, so BOTH spellings must be
# accepted here — an assertion demanding the literal string the Dockerfile uses
# would fail on a healthy image, which is the loudest possible wrong answer.
comps=$(cd "$WORKDIR" && rustup component list --installed 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
  # Deliberately a different message from "a component is missing": one is
  # rustup not answering, the other is rustup answering that it has nothing.
  # Sharing a voice would leave the build log unable to say which happened.
  bad "rustup could not list installed components (exit $rc): $comps
        This is rustup failing to answer, NOT a component being absent. Nothing below
        was checked, so do not read the absence of component failures as their presence."
else
  for c in clippy llvm-tools; do
    if printf '%s\n' "$comps" | grep -Eq "^${c}(-preview)?(-|\$)"; then
      ok "rustup component $c is installed"
    else
      bad "rustup component $c is NOT installed in this image. No check declares it and no
        \`tools:\` list can: it is a component of the pinned toolchain, not a program a
        command invokes, so the run-time tools gate cannot refuse 97 for it. Without it
        $( [ "$c" = clippy ] && echo "\`just clippy\` (cargo cranky)" || echo "\`cargo llvm-cov test\`" ) fails
        in the ORDINARY range and reads as upstream's verdict on our code."
    fi
  done
fi

echo
[ "$fails" -eq 0 ] && { echo "assert-toolchain: PASS"; exit 0; }
echo "assert-toolchain: FAILURES -- refusing to tag this image" >&2
exit 1
