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

# PyYAML is not a PATH entry, so the tools gate in run-check.sh structurally
# cannot see it. check-schema-compat.sh imports checks_lib, which imports yaml.
if python3 -c "import yaml" >/dev/null 2>&1; then ok "python3 can import yaml (PyYAML)"
else bad "python3 cannot import yaml; check-schema-compat.sh would refuse 93 reading its own baseline"; fi

echo
[ "$fails" -eq 0 ] && { echo "assert-toolchain: PASS"; exit 0; }
echo "assert-toolchain: FAILURES -- refusing to tag this image" >&2
exit 1
