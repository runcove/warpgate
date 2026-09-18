#!/usr/bin/env bash
# The cap assertion is the whole point of this script. These tests exist to prove
# it FAILS when the cap is absent -- a cap that is merely requested and never
# verified is what upstream has, and it is what let a build take the cluster down.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${HARDENED_RUN:-$HERE/../hardened-run.sh}"
FIXTURES="$HERE/fixtures"
fails=0
skips=0
ok()   { echo "  ok    $1"; }
bad()  { echo "  FAIL  $1"; fails=1; }
skip() { echo "  SKIP  $1"; skips=$((skips + 1)); }

# Cases 1-11 drive hardened-run.sh's own test hooks (HARDENED_RUN_DRY,
# HARDENED_RUN_FAKE_INSPECT*), which fix round 1 makes fatal to use inside a
# real CI run (see cases 12-14). Clear any ambient CI markers so this suite
# keeps working when it is itself run as a check under real Forgejo Actions.
unset CI GITHUB_ACTIONS FORGEJO_ACTIONS

# Scratch dir for "did docker exec actually run" marker files. Not mktemp
# (blocked in this environment) -- a PID-suffixed dir under TMPDIR, same
# pattern a real CI runner's own tmp would give it.
MARKER_DIR="${TMPDIR:-/tmp}/hardened-run-test.$$"
mkdir -p "$MARKER_DIR"
trap 'rm -rf "$MARKER_DIR"' EXIT

# 1. The invocation carries the caps we asked for.
out=$(HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1)
grep -q -- "--cpus=4"   <<<"$out" && ok "cpu cap appears in the invocation"   || bad "cpu cap missing: $out"
grep -q -- "--memory=7g" <<<"$out" && ok "memory cap appears in the invocation" || bad "memory cap missing: $out"

# 2. Memory-swap must equal memory. Without it the container swaps instead of
#    being killed, and the cap silently does not bound anything.
grep -q -- "--memory-swap=7g" <<<"$out" && ok "memory-swap pinned to memory" \
  || bad "memory-swap not pinned -- the cap does not bound the build: $out"

# 3. A missing cap argument is refused outright rather than defaulted.
#    HARDENED_RUN_IMAGE is exported and a stub `docker` put on PATH so that,
#    if the memory-required guard is ever deleted, this case fails for THAT
#    reason -- not because `${HARDENED_RUN_IMAGE:?}` or a missing `docker`
#    binary dies first, both of which used to make this case pass "ok" even
#    with the guard gone (fix round 1, finding 3).
(
  export PATH="$FIXTURES:$PATH"
  export HARDENED_RUN_IMAGE=stub-image
  export STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000
  "$SCRIPT" --cpus 4 -- true >/dev/null 2>&1
)
[ $? -ne 0 ] && ok "refuses to run without a memory cap" \
  || bad "ran with no memory cap -- this is the 2026-09-15 incident"

# 4. THE NEGATIVE THAT MAKES THE REST MEAN ANYTHING: when the runtime reports a
#    cap of 0 (i.e. no cap took effect), the script must exit 90, not succeed.
out=$(HARDENED_RUN_DRY=1 HARDENED_RUN_FAKE_INSPECT=0 \
      "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 when the runtime reports no cap" \
  || bad "did not fail on an absent cap (rc=$rc) -- the assertion is decorative"
grep -qi "cap" <<<"$out" && ok "says what went wrong" || bad "failed silently"

# 5. A cap that IS present must not trip the assertion.
HARDENED_RUN_DRY=1 HARDENED_RUN_FAKE_INSPECT=7516192768 \
  "$SCRIPT" --cpus 4 --memory 7g -- true >/dev/null 2>&1
[ $? -eq 0 ] && ok "passes when the cap is really in place" \
  || bad "false alarm on a good cap"

# 6. Nothing Warpgate-specific (spec ruling 2: this must generalise).
if grep -qi "warpgate" "$SCRIPT"; then
  bad "contains 'warpgate' -- it is supposed to be reusable by cove and ch"
else ok "no repo-specific content"; fi

# 7-11. FIX ROUND 1, finding 1: the wrapper must tell "capped" from "could not
# tell", exercised through a stub `docker` on PATH so the real (non-dry)
# inspect path actually runs -- HARDENED_RUN_DRY/HARDENED_RUN_FAKE_INSPECT
# never reach this code at all.

# 7. An inspect that fails outright must not let the command run. Before the
#    fix, a failed `docker inspect` was silently swallowed (`2>/dev/null`),
#    producing an empty ACTUAL that skipped the "== 0" check and fell
#    through to `docker exec`. Reproduced by the reviewer with this exact
#    stub.
marker="$MARKER_DIR/exec-ran-7"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_INSPECT_RC=1 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 when docker inspect itself fails" \
  || bad "did not exit 90 on a failed inspect (rc=$rc): $out"
grep -qi "cap" <<<"$out" && ok "names the cap when inspect fails" || bad "failed silently: $out"
[ ! -e "$marker" ] && ok "the command never ran after a failed inspect" \
  || bad "docker exec ran despite a failed inspect -- the assertion is decorative"

# 8. A non-numeric inspect result must not let the command run either.
marker="$MARKER_DIR/exec-ran-8"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM="<none>" STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 on a non-numeric inspect result" \
  || bad "did not exit 90 on garbage inspect output (rc=$rc): $out"
[ ! -e "$marker" ] && ok "the command never ran after a garbage inspect" \
  || bad "docker exec ran despite a garbage inspect result"

# 9. A numeric cap that is merely WRONG -- not literally "0" -- must also
#    refuse. The old check only ever compared against the string "0", so a
#    runtime silently capping at, say, half of what was asked would have
#    sailed straight through it.
marker="$MARKER_DIR/exec-ran-9"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=1073741824 STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "exits 90 when the runtime's cap doesn't match what was requested" \
  || bad "accepted a mismatched cap (rc=$rc): $out"
[ ! -e "$marker" ] && ok "the command never ran with a mismatched cap" \
  || bad "docker exec ran despite a mismatched cap"

# 10. Asking for 0 and getting 0 back must still refuse. A pure "actual ==
#     expected" comparison would treat this as consistent; docker's own
#     semantics say a cap of 0 always means "no cap took effect", regardless
#     of what was requested, so that reading must be checked unconditionally
#     and not just as one side of an equality test. (Found via the fix-3
#     deletion mutant below, which showed exactly this gap before this case
#     existed.)
marker="$MARKER_DIR/exec-ran-10"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=0 STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 0 -- true 2>&1
); rc=$?
[ "$rc" -eq 90 ] && ok "refuses even when 0 was requested and 0 came back" \
  || bad "accepted a requested-and-actual cap of 0 (rc=$rc): $out"
[ ! -e "$marker" ] && ok "the command never ran with a 0/0 cap" \
  || bad "docker exec ran despite a 0/0 cap"

# 11. Sanity: a real run where both caps genuinely match must still succeed
#     and actually run the command -- fix 1 must not turn this into a
#     wrapper that never runs anything.
marker="$MARKER_DIR/exec-ran-11"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 STUB_DOCKER_EXEC_MARKER="$marker" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 0 ] && ok "a genuinely correct real cap still succeeds" \
  || bad "false alarm on a real, correct cap (rc=$rc): $out"
[ -e "$marker" ] && ok "the command actually ran when the cap was correct" \
  || bad "the command never ran even though the cap was correct"

# 12-14. FIX ROUND 1, finding 2: a leaked test hook must fail loudly under
# CI, not run silently as a no-op.

# 12. HARDENED_RUN_DRY alone would otherwise turn a real build step into a
#     green no-op if it leaked in via a copied env: block or a prior step's
#     GITHUB_ENV.
out=$(CI=true HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses a leaked HARDENED_RUN_DRY under CI" \
  || bad "did not refuse HARDENED_RUN_DRY under CI (rc=$rc): $out"
grep -q "HARDENED_RUN_DRY" <<<"$out" && ok "names HARDENED_RUN_DRY as the offender" \
  || bad "did not name the offending variable: $out"

# 13. Same for HARDENED_RUN_FAKE_INSPECT, which alone makes the script
#     report success without ever calling docker run or docker inspect.
out=$(GITHUB_ACTIONS=true HARDENED_RUN_FAKE_INSPECT=7516192768 \
      "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses a leaked HARDENED_RUN_FAKE_INSPECT under CI" \
  || bad "did not refuse HARDENED_RUN_FAKE_INSPECT under CI (rc=$rc): $out"
grep -q "HARDENED_RUN_FAKE_INSPECT" <<<"$out" && ok "names HARDENED_RUN_FAKE_INSPECT as the offender" \
  || bad "did not name the offending variable: $out"

# 14. Not named in the brief's wording of fix 2, but the same leak would
#     defeat the same guard for the CPU-side fake hook fix 1 adds alongside
#     the existing memory one, so it gets the same treatment.
out=$(FORGEJO_ACTIONS=true HARDENED_RUN_FAKE_INSPECT_CPUS=4000000000 \
      "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses a leaked HARDENED_RUN_FAKE_INSPECT_CPUS under CI" \
  || bad "did not refuse HARDENED_RUN_FAKE_INSPECT_CPUS under CI (rc=$rc): $out"
grep -q "HARDENED_RUN_FAKE_INSPECT_CPUS" <<<"$out" && ok "names HARDENED_RUN_FAKE_INSPECT_CPUS as the offender" \
  || bad "did not name the offending variable: $out"

# 15. TASK 4 FIX ROUND 1 (contract fix, authorised there): a missing
#     HARDENED_RUN_IMAGE must exit 93 ("required configuration missing"),
#     not bash's own `${VAR:?}` exit status 1 -- which is indistinguishable
#     from an ordinary script crash and sits outside this file's exit-code
#     contract entirely, defeating any caller (run-check.sh included) that
#     tries to treat the 89-99 band as "did not run safely". Deliberately no
#     stub docker on PATH: the fix must refuse before ever trying to invoke
#     docker, real or fake, so a leftover attempt to run it would surface
#     here as some other rc (e.g. 127, command not found), not 93.
out=$(unset HARDENED_RUN_IMAGE; "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "missing HARDENED_RUN_IMAGE exits 93, not a bare 1" \
  || bad "missing HARDENED_RUN_IMAGE did not exit 93 (rc=$rc): $out"
# NOT `grep -qi "HARDENED_RUN_IMAGE"` -- bash's own pre-fix `${VAR:?}` error
# ("...: line N: HARDENED_RUN_IMAGE: set HARDENED_RUN_IMAGE") ALSO mentions
# the variable name, so that grep alone survives the very mutation it exists
# to catch. Anchor to text only this script's own refusal message produces.
grep -q "hardened-run: FATAL -- HARDENED_RUN_IMAGE is not set" <<<"$out" \
  && ok "names the missing configuration in our own refusal message, not bash's builtin :? text" \
  || bad "did not produce our own refusal message: $out"

# 16-20. TASK 5 FIX ROUND 1 (gap traced to Task 2's own brief text, authorised
# there): --forward-env crosses the cap boundary that used to forward
# nothing at all. The caller passes a variable NAME; the VALUE is read from
# this script's own environment by docker's `-e VAR` (name-only) form, so it
# is never a command-line argument, never in a `set -x` trace, never in a
# process listing. Cases 19 exercise the stub `docker`'s own recorded argv,
# not just this script's claim about itself.

# 16. Dry preview must show the -e flag -- the preview is the only handle a
#     dry test has on the flag's effect, and HARDENED_RUN_DRY=1 must include
#     it per the fix-round brief.
out=$(HARDENED_RUN_DRY=1 FOO_VAR=somevalue \
      "$SCRIPT" --cpus 4 --memory 7g --forward-env FOO_VAR -- true 2>&1)
grep -q -- "-e FOO_VAR" <<<"$out" && ok "dry preview includes the forwarded -e flag" \
  || bad "dry preview omitted the forwarded flag: $out"
grep -q "forwarded 1 variable(s) into the capped container: FOO_VAR" <<<"$out" \
  && ok "names what it forwarded, by name and count" \
  || bad "did not report the forward by name and count: $out"

# 17. A variable that is genuinely unset must not be forwarded -- this is the
#     exact shape of a cache-env.sh refusal (Task 3): GITHUB_ENV never gets
#     RUSTC_WRAPPER, so the job process never has it at all. `-e VAR` on an
#     unset VAR would still define it as empty inside the container.
out=$(unset MISSING_VAR; HARDENED_RUN_DRY=1 \
      "$SCRIPT" --cpus 4 --memory 7g --forward-env MISSING_VAR -- true 2>&1)
grep -q -- "-e MISSING_VAR" <<<"$out" \
  && bad "forwarded an unset variable -- would define it empty in the container: $out" \
  || ok "an unset variable is not forwarded"
grep -q "forwarded 0 variable(s)" <<<"$out" && ok "count reflects nothing forwarded" \
  || bad "count did not reflect the skip: $out"

# 18. A variable that is SET but empty (an unconfigured Actions secret still
#     lands in job env as "") must also not be forwarded -- an empty
#     AWS_SECRET_ACCESS_KEY inside the container is worse than an absent
#     one: sccache starts, fails auth, and the failure reads as a
#     configuration bug rather than the absent-cache problem it is.
out=$(EMPTY_VAR="" HARDENED_RUN_DRY=1 \
      "$SCRIPT" --cpus 4 --memory 7g --forward-env EMPTY_VAR -- true 2>&1)
grep -q -- "-e EMPTY_VAR" <<<"$out" \
  && bad "forwarded an empty-but-set variable: $out" \
  || ok "an empty-but-set variable is not forwarded"

# 19. The stub docker's OWN recorded argv -- not this script's claim about
#     itself -- must show the -e flag on both `docker run -d` and
#     `docker exec`. Runs the real (non-dry) path via the stub so both calls
#     actually happen.
RUN_ARGS_FILE="$MARKER_DIR/run-args-19"
EXEC_ARGS_FILE="$MARKER_DIR/exec-args-19"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_RUN_ARGS_FILE="$RUN_ARGS_FILE" STUB_DOCKER_EXEC_ARGS_FILE="$EXEC_ARGS_FILE" \
  FORWARD_ME=abc123 \
  "$SCRIPT" --cpus 4 --memory 7g --forward-env FORWARD_ME -- true 2>&1
); rc=$?
[ "$rc" -eq 0 ] && ok "a forwarded run still succeeds" || bad "forwarded run failed (rc=$rc): $out"
grep -qx -- "-e" "$RUN_ARGS_FILE" 2>/dev/null && grep -qx "FORWARD_ME" "$RUN_ARGS_FILE" \
  && ok "docker run actually received -e FORWARD_ME" \
  || bad "docker run's real argv did not carry -e FORWARD_ME: $(cat "$RUN_ARGS_FILE" 2>/dev/null)"
grep -qx -- "-e" "$EXEC_ARGS_FILE" 2>/dev/null && grep -qx "FORWARD_ME" "$EXEC_ARGS_FILE" \
  && ok "docker exec actually received -e FORWARD_ME" \
  || bad "docker exec's real argv did not carry -e FORWARD_ME: $(cat "$EXEC_ARGS_FILE" 2>/dev/null)"

# 20. Never the value -- only the name -- in anything this script itself
#     prints. The dummy value is deliberately distinctive so it would be easy
#     to spot if it leaked into the "forwarded" report or the dry preview.
out=$(HARDENED_RUN_DRY=1 SECRETY_VAR="do-not-print-me-98765" \
      "$SCRIPT" --cpus 4 --memory 7g --forward-env SECRETY_VAR -- true 2>&1)
grep -q "do-not-print-me-98765" <<<"$out" \
  && bad "the forwarded value leaked into this script's own output: $out" \
  || ok "only the variable name is reported, never its value"

# 21. TASK 7B: regression. With no --source, the final `docker exec` must
#     carry no --workdir flag at all -- "when --source is absent, behaviour
#     is exactly as today" is the explicit contract, checked against the
#     stub docker's own recorded argv, not this script's claim about itself.
EXEC_ARGS_FILE_21="$MARKER_DIR/exec-args-21"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_EXEC_ARGS_FILE="$EXEC_ARGS_FILE_21" \
  "$SCRIPT" --cpus 4 --memory 7g -- true 2>&1
); rc=$?
[ "$rc" -eq 0 ] && ok "a bare run with no --source still succeeds" \
  || bad "bare run regressed (rc=$rc): $out"
grep -qx -- "--workdir" "$EXEC_ARGS_FILE_21" 2>/dev/null \
  && bad "docker exec carries --workdir even though --source was never given: $(cat "$EXEC_ARGS_FILE_21" 2>/dev/null)" \
  || ok "no --source: docker exec carries no --workdir flag"

# 22-23. Usage errors: --source and --workdir must be given together (run-check.sh
# always passes both). No container runtime involved -- refused at parse time.
out=$(HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g --source /tmp -- true 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "refuses --source without --workdir (exit 2)" \
  || bad "did not refuse --source without --workdir (rc=$rc): $out"

out=$(HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g --workdir /src -- true 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "refuses --workdir without --source (exit 2)" \
  || bad "did not refuse --workdir without --source (rc=$rc): $out"

# 24-29. --source delivery, proven against a REAL container -- not a stub.
# `docker cp`'s contents-vs-directory distinction (the actual bug class this
# task exists to close) cannot be proven by a stub that just returns
# whatever exit code a test tells it to; only a genuine copy into a genuine
# container proves the trailing "/." landed the files unnested. Prefers a
# real `docker` binary when present (real CI: docker:28-dind); this
# development host has no docker at all, so this falls back to a `docker`
# shim over `podman` -- verified by hand against `alpine` beforehand
# (run/exec/cp/inspect/rm all match docker's documented behaviour, including
# the cp contents-vs-directory distinction) before being relied on here.
# With neither available, these cases are SKIPPED and say so loudly -- never
# silently counted as passing.
REAL_ENGINE=""
ENGINE_PATH_PREFIX=""
if command -v docker >/dev/null 2>&1; then
  REAL_ENGINE=docker
elif command -v podman >/dev/null 2>&1; then
  REAL_ENGINE=podman
  ENGINE_BIN_DIR="$MARKER_DIR/engine-bin"
  mkdir -p "$ENGINE_BIN_DIR"
  cat > "$ENGINE_BIN_DIR/docker" <<'SHIM'
#!/usr/bin/env bash
exec podman "$@"
SHIM
  chmod +x "$ENGINE_BIN_DIR/docker"
  ENGINE_PATH_PREFIX="$ENGINE_BIN_DIR:"
fi

if [ -z "$REAL_ENGINE" ]; then
  skip "no real container runtime (docker or podman) on PATH -- cases 24-29 (real --source delivery) cannot be proven here"
else
  TEST_IMAGE="${HARDENED_RUN_TEST_IMAGE:-docker.io/library/alpine:latest}"
  if PATH="${ENGINE_PATH_PREFIX}$PATH" timeout 90 docker pull "$TEST_IMAGE" >/dev/null 2>&1; then
    SRC_DIR="$MARKER_DIR/real-src"
    mkdir -p "$SRC_DIR"
    echo "[package]" > "$SRC_DIR/Cargo.toml"
    echo "marker-content-24" > "$SRC_DIR/marker.txt"

    # 24. Positive: a real copy + verification lets the command run, and the
    #     command genuinely sees the copied file's content -- not a stub
    #     claiming it did.
    out=$(
      PATH="${ENGINE_PATH_PREFIX}$PATH" HARDENED_RUN_IMAGE="$TEST_IMAGE" \
      "$SCRIPT" --cpus 1 --memory 256m --source "$SRC_DIR" --workdir /src \
        -- cat /src/marker.txt 2>&1
    ); rc=$?
    [ "$rc" -eq 0 ] && ok "real source delivery + verification lets the command run" \
      || bad "real source delivery failed (rc=$rc): $out"
    grep -q "marker-content-24" <<<"$out" && ok "the command saw the copied file's real content" \
      || bad "copied content not visible inside the real container: $out"

    # 25. --workdir is genuinely applied to the real `docker exec`, not just
    #     asserted -- checked via `pwd` inside the running container.
    out=$(
      PATH="${ENGINE_PATH_PREFIX}$PATH" HARDENED_RUN_IMAGE="$TEST_IMAGE" \
      "$SCRIPT" --cpus 1 --memory 256m --source "$SRC_DIR" --workdir /src \
        -- pwd 2>&1
    )
    grep -qx "/src" <<<"$out" && ok "the real docker exec actually runs with --workdir /src" \
      || bad "workdir not applied to the real exec: $out"

    # 26. Contents form, not nested: Cargo.toml lands directly at
    #     $WORKDIR/Cargo.toml, proving "SRC/." (contents) was used, not
    #     "SRC" (which would nest everything one level deeper).
    PATH="${ENGINE_PATH_PREFIX}$PATH" HARDENED_RUN_IMAGE="$TEST_IMAGE" \
      "$SCRIPT" --cpus 1 --memory 256m --source "$SRC_DIR" --workdir /src \
        -- test -f /src/Cargo.toml >/dev/null 2>&1
    [ $? -eq 0 ] && ok "source landed unnested at \$WORKDIR/Cargo.toml (contents form)" \
      || bad "source nested one level deeper than expected -- SRC vs SRC/. got mixed up"

    # 27. A --source directory that does not exist: docker cp itself fails,
    #     refused with 98, naming docker cp as the failing step.
    out=$(
      PATH="${ENGINE_PATH_PREFIX}$PATH" HARDENED_RUN_IMAGE="$TEST_IMAGE" \
      "$SCRIPT" --cpus 1 --memory 256m --source "$MARKER_DIR/no-such-source-27" --workdir /src \
        -- true 2>&1
    ); rc=$?
    [ "$rc" -eq 98 ] && ok "a nonexistent --source dir refuses with 98" \
      || bad "nonexistent --source did not refuse with 98 (rc=$rc): $out"
    grep -qi "docker cp" <<<"$out" && ok "names docker cp as the failing step" \
      || bad "did not say docker cp failed: $out"

    # 28. A --workdir that cannot be created (an existing FILE of that name
    #     inside the image) fails the mkdir step specifically, worded
    #     distinctly from the docker-cp and verification failures -- so a
    #     reader can tell which of the three things went wrong.
    out=$(
      PATH="${ENGINE_PATH_PREFIX}$PATH" HARDENED_RUN_IMAGE="$TEST_IMAGE" \
      "$SCRIPT" --cpus 1 --memory 256m --source "$SRC_DIR" --workdir /bin/busybox \
        -- true 2>&1
    ); rc=$?
    [ "$rc" -eq 98 ] && ok "a workdir that cannot be created refuses with 98" \
      || bad "uncreatable workdir did not refuse with 98 (rc=$rc): $out"
    grep -qi "could not create" <<<"$out" && ok "names the mkdir step as the failing one, distinctly" \
      || bad "did not distinguish the mkdir failure from a cp or verify failure: $out"

    # 29. THE MUTATION: on a disposable copy of the script (never the shared
    #     checkout, never git stash -- several sessions share this tree),
    #     neuter the real `docker cp` call so it silently no-ops. If the
    #     verification step were decorative, this mutant would report
    #     success against an empty $WORKDIR exactly like the bug this task
    #     exists to close. The diff is checked to touch exactly the one
    #     intended line before the mutant is trusted.
    MUTANT_DIR="$MARKER_DIR/mutant"
    mkdir -p "$MUTANT_DIR"
    sed 's#docker cp "\$SOURCE/\."#true "$SOURCE/."#' "$SCRIPT" > "$MUTANT_DIR/hardened-run.sh"
    chmod +x "$MUTANT_DIR/hardened-run.sh"
    DIFF_OUT=$(diff "$SCRIPT" "$MUTANT_DIR/hardened-run.sh")
    DIFF_LINES=$(wc -l <<<"$DIFF_OUT")
    if [ "$DIFF_LINES" -eq 4 ] && grep -q '^< .*docker cp' <<<"$DIFF_OUT" \
       && grep -q '^> .*true ' <<<"$DIFF_OUT"; then
      ok "mutation touched exactly the intended docker cp line, nothing else"
    else
      bad "mutation diff is not the single expected line change -- not trusting this mutant: $DIFF_OUT"
    fi
    mutant_out=$(
      PATH="${ENGINE_PATH_PREFIX}$PATH" HARDENED_RUN_IMAGE="$TEST_IMAGE" \
      "$MUTANT_DIR/hardened-run.sh" --cpus 1 --memory 256m --source "$SRC_DIR" --workdir /src \
        -- true 2>&1
    ); mutant_rc=$?
    [ "$mutant_rc" -eq 98 ] && \
      ok "a neutered docker cp is still caught by the verification step and refuses with 98" \
      || bad "a silently no-op'd copy step was NOT caught (rc=$mutant_rc) -- the verification is decorative: $mutant_out"
  else
    skip "could not pull $TEST_IMAGE (no network?) -- cases 24-29 (real --source delivery) skipped"
  fi
fi

# ---------------------------------------------------------------------------
# TASK 7B, FIX ROUND 1: --verify-file. The original submission hardcoded
# "Cargo.toml" inside hardened-run.sh itself, which contradicts this file's
# own header ("Reusable: nothing in here names a project") -- that knowledge
# now belongs to the CALLER (run-check.sh passes --verify-file Cargo.toml;
# see run-check.sh's own tests for that assertion). Cases 30-36 below cover
# the new flag and its four 98 paths using ONLY the stub docker fixture
# above -- never a real container -- because control of podman/docker in
# THIS session was withdrawn mid-arc pending a permissions ruling the
# controller escalated to Jeremy (the standing rule: a lead's limits are its
# workers' limits). Cases 24-29 above, which DO use a real engine, are left
# exactly as originally committed and were NOT re-run after this change:
# reasoning through them says they still hold (none of their assertions
# depend on which of the two verification strengths ran -- they either fail
# before reaching verification at all, or only check the outcome of the
# caller's own real command), but that is analysis, not evidence, and is
# reported as such rather than re-proven by the now-off-limits route.
# ---------------------------------------------------------------------------

# 30. Usage: --verify-file requires --source. No container involved.
out=$(HARDENED_RUN_DRY=1 "$SCRIPT" --cpus 4 --memory 7g --verify-file Cargo.toml -- true 2>&1); rc=$?
[ "$rc" -eq 2 ] && ok "refuses --verify-file without --source (exit 2)" \
  || bad "did not refuse --verify-file without --source (rc=$rc): $out"

# 31. --verify-file given, the container-side `test -f` fails: refuses 98,
#     names the specific file, and the real command never runs.
marker31="$MARKER_DIR/exec-ran-31"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_EXEC_TEST_RC=1 STUB_DOCKER_EXEC_MARKER="$marker31" \
  "$SCRIPT" --cpus 4 --memory 7g --source /fake/src --workdir /src \
    --verify-file Cargo.toml -- true 2>&1
); rc=$?
[ "$rc" -eq 98 ] && ok "a --verify-file that isn't found refuses with 98" \
  || bad "missing --verify-file did not refuse with 98 (rc=$rc): $out"
grep -q "src/Cargo.toml" <<<"$out" && ok "names the specific verify-file path" \
  || bad "did not name the verify-file path: $out"
[ ! -e "$marker31" ] && ok "the real command never ran after a failed verify-file check" \
  || bad "the real command ran despite a failed verify-file check"

# 32. --verify-file given, the container-side `test -f` succeeds: the real
#     command actually runs.
marker32="$MARKER_DIR/exec-ran-32"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_EXEC_TEST_RC=0 STUB_DOCKER_EXEC_MARKER="$marker32" \
  "$SCRIPT" --cpus 4 --memory 7g --source /fake/src --workdir /src \
    --verify-file Cargo.toml -- true 2>&1
); rc=$?
[ "$rc" -eq 0 ] && ok "a --verify-file that IS found lets the run succeed" \
  || bad "a satisfied --verify-file still failed (rc=$rc): $out"
[ -e "$marker32" ] && ok "the real command actually ran after a satisfied verify-file check" \
  || bad "the real command never ran despite a satisfied verify-file check"

# 33. No --verify-file: the weaker check. An empty workdir (the `find`
#     reports nothing) refuses with 98, says the check was the weaker one,
#     and the real command never runs.
marker33="$MARKER_DIR/exec-ran-33"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_EXEC_MARKER="$marker33" \
  "$SCRIPT" --cpus 4 --memory 7g --source /fake/src --workdir /src -- true 2>&1
); rc=$?
[ "$rc" -eq 98 ] && ok "no --verify-file, empty workdir: refuses with 98" \
  || bad "empty workdir with no --verify-file did not refuse with 98 (rc=$rc): $out"
grep -qi "empty" <<<"$out" && ok "says the workdir came back empty" \
  || bad "did not say the workdir was empty: $out"
grep -qi "verify-file" <<<"$out" && ok "flags this as the weaker, no --verify-file check" \
  || bad "did not say this was the weaker check: $out"
[ ! -e "$marker33" ] && ok "the real command never ran against an empty workdir" \
  || bad "the real command ran despite an empty workdir"

# 34. No --verify-file, a non-empty workdir (`find` reports something): the
#     weaker check is satisfied and the real command runs.
marker34="$MARKER_DIR/exec-ran-34"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_EXEC_FIND_OUTPUT="/src/some-file" STUB_DOCKER_EXEC_MARKER="$marker34" \
  "$SCRIPT" --cpus 4 --memory 7g --source /fake/src --workdir /src -- true 2>&1
); rc=$?
[ "$rc" -eq 0 ] && ok "no --verify-file, non-empty workdir: succeeds" \
  || bad "non-empty workdir with no --verify-file still failed (rc=$rc): $out"
[ -e "$marker34" ] && ok "the real command actually ran with a non-empty workdir" \
  || bad "the real command never ran despite a non-empty workdir"

# 35. The mkdir step itself failing refuses with 98, names mkdir
#     specifically, and the real command never runs -- the stub-driven
#     counterpart of case 28 above (which proved this against a real
#     container before this session's container access was withdrawn).
marker35="$MARKER_DIR/exec-ran-35"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_EXEC_MKDIR_RC=1 STUB_DOCKER_EXEC_MARKER="$marker35" \
  "$SCRIPT" --cpus 4 --memory 7g --source /fake/src --workdir /src \
    --verify-file Cargo.toml -- true 2>&1
); rc=$?
[ "$rc" -eq 98 ] && ok "a failed mkdir refuses with 98" \
  || bad "failed mkdir did not refuse with 98 (rc=$rc): $out"
grep -qi "could not create" <<<"$out" && ok "names mkdir as the failing step" \
  || bad "did not name mkdir as the failing step: $out"
[ ! -e "$marker35" ] && ok "the real command never ran after a failed mkdir" \
  || bad "the real command ran despite a failed mkdir"

# 36. docker cp itself failing refuses with 98, names docker cp
#     specifically, and the real command never runs -- the stub-driven
#     counterpart of case 27 above.
marker36="$MARKER_DIR/exec-ran-36"
out=$(
  PATH="$FIXTURES:$PATH" HARDENED_RUN_IMAGE=stub-image \
  STUB_DOCKER_MEM=7516192768 STUB_DOCKER_NANOCPUS=4000000000 \
  STUB_DOCKER_CP_RC=1 STUB_DOCKER_EXEC_MARKER="$marker36" \
  "$SCRIPT" --cpus 4 --memory 7g --source /fake/src --workdir /src \
    --verify-file Cargo.toml -- true 2>&1
); rc=$?
[ "$rc" -eq 98 ] && ok "a failed docker cp refuses with 98" \
  || bad "failed docker cp did not refuse with 98 (rc=$rc): $out"
grep -qi "docker cp itself failed" <<<"$out" && ok "names docker cp as the failing step" \
  || bad "did not name docker cp as the failing step: $out"
[ ! -e "$marker36" ] && ok "the real command never ran after a failed docker cp" \
  || bad "the real command ran despite a failed docker cp"

echo
echo "skipped: $skips"
[ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
