#!/usr/bin/env bash
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${RUN_CHECK:-$HERE/../run-check.sh}"
fails=0
ok()  { echo "  ok    $1"; }
bad() { echo "  FAIL  $1"; fails=1; }

# Cases below exercise run-check.sh's own CI-leak guard (RUN_CHECK_DRY,
# RUN_CHECK_FORCE_STATE, RUN_CHECK_FORCE_RC under CI/GITHUB_ACTIONS/
# FORGEJO_ACTIONS). Clear any ambient CI markers first so the cases above
# and below that one stay deterministic regardless of how this suite itself
# is invoked -- mirrors test-hardened-run.sh.
unset CI GITHUB_ACTIONS FORGEJO_ACTIONS

# A reporting check that FAILS must not fail the job.
out=$(RUN_CHECK_FORCE_RC=1 "$SCRIPT" cargo-deny 2>&1); rc=$?
[ $rc -eq 0 ] && ok "a failing reporting check does not fail the job" \
  || bad "reporting check failed the job (rc=$rc)"
grep -qi "report" <<<"$out" && ok "says it is report-only" || bad "silent about being report-only: $out"

# A blocking check that FAILS must fail the job. Without this, promoting a check
# to blocking would change nothing at all.
out=$(RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=1 "$SCRIPT" cargo-deny 2>&1); rc=$?
[ $rc -ne 0 ] && ok "a failing blocking check fails the job" \
  || bad "blocking check passed while failing -- promotion would be meaningless"

# A blocking check that PASSES must pass.
RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=0 "$SCRIPT" cargo-deny >/dev/null 2>&1
[ $? -eq 0 ] && ok "a passing blocking check passes" || bad "false alarm on a good check"

# An excepted check is skipped, and says why and until when.
out=$("$SCRIPT" reprotest 2>&1); rc=$?
[ $rc -eq 0 ] && ok "excepted check does not fail the job" || bad "excepted check failed (rc=$rc)"
grep -qi "review_by\|2026-12-18" <<<"$out" && ok "names the review date" \
  || bad "skipped silently -- indistinguishable from a deleted check: $out"

# A compiling check must go through the hardened wrapper; a non-compiling one must not.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>&1)
grep -q "hardened-run" <<<"$out" && ok "compiling check is capped" \
  || bad "clippy ran uncapped -- see global constraints: $out"
out=$(RUN_CHECK_DRY=1 "$SCRIPT" cargo-deny 2>&1)
grep -q "hardened-run" <<<"$out" && bad "non-compiling check needlessly capped" \
  || ok "non-compiling check runs directly"

# 'unverified' must be treated as compiling -- the safe direction.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" schema-compat 2>&1)
grep -q "hardened-run" <<<"$out" && ok "'unverified' is treated as compiling" \
  || bad "'unverified' ran uncapped -- unsafe default: $out"

# THE CACHE PROBE (added after run 573). A capped command must carry the probe
# that degrades to an uncached build when sccache cannot start, because
# RUSTC_WRAPPER fronts every rustc call and a dead sccache otherwise breaks
# checks that never wanted a cache. Asserted through the dry run because, as
# with the tools gate, this is the only place the composed command can be
# observed without a container engine, and baba has none.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>&1)
grep -q 'RUSTC_WRAPPER' <<<"$out" \
  && ok "capped command carries the cache probe" \
  || bad "capped command has no cache probe -- a dead cache would break the check instead of slowing it: $out"
grep -q 'unset RUSTC_WRAPPER' <<<"$out" \
  && ok "the probe DEGRADES (unsets the wrapper) rather than refusing" \
  || bad "probe does not unset RUSTC_WRAPPER -- a cache outage would turn the run red: $out"
grep -q 'CACHE-UNAVAILABLE' <<<"$out" \
  && ok "the probe emits a greppable CACHE-UNAVAILABLE marker for the run summary" \
  || bad "probe is silent -- a cache dead for a week would become the new normal: $out"

# The uncapped path must NOT carry it: those checks never enter the sandbox,
# so sccache is neither present nor relevant there. Without this, the probe
# could be pasted onto every command and both assertions above would still
# pass, proving only that the string exists somewhere.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" cargo-deny 2>&1)
grep -q 'CACHE-UNAVAILABLE' <<<"$out" \
  && bad "uncapped check carries the cache probe, which runs in a container it never enters: $out" \
  || ok "uncapped check carries no cache probe"

# THE POSITIVE READING (runcove-vhkg). CACHE-UNAVAILABLE above is a NEGATIVE
# marker: its absence is consistent both with a cache that read everything and
# with a cache nobody ever switched on. Proving the read path on 19 Sep 2026
# took a bucket-object counter bound to check boundaries plus three converging
# non-timing arguments, none of which came from the run. These cases assert the
# run now says it itself.
out=$(RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>&1)
grep -q 'CACHE-STATS' <<<"$out" \
  && ok "capped command carries a positive cache reading" \
  || bad "capped command emits no CACHE-STATS -- a working cache and a skipped probe stay identical: $out"
grep -q 'trap __cache_stats EXIT' <<<"$out" \
  && ok "the reading is on an EXIT trap, so it survives a failing or exiting check" \
  || bad "CACHE-STATS is not on an EXIT trap -- the reading would be lost exactly when a check dies, which is when it is wanted: $out"
out=$(RUN_CHECK_DRY=1 "$SCRIPT" cargo-deny 2>&1)
grep -q 'CACHE-STATS' <<<"$out" \
  && bad "uncapped check carries the stats epilogue, which reads an sccache that is not in its container: $out" \
  || ok "uncapped check carries no stats epilogue"

# Behavioural, not textual. Everything above proves a string was composed; the
# cases below RUN the composed command with fakes for the three tools clippy
# declares (just, cargo, cargo-cranky) and for sccache, so the probe's actual
# behaviour is observed rather than inferred. This is the same gap that let a
# 291-green selftest suite stay silent about the only path that mattered.
probe_fakes() {
  # $1 = dir, $2 = sccache mode, $3 = rc for the fake `just`
  mkdir -p "$1"
  printf '#!/bin/sh\nexit %s\n' "$3" > "$1/just"
  printf '#!/bin/sh\nexit 0\n' > "$1/cargo"
  printf '#!/bin/sh\nexit 0\n' > "$1/cargo-cranky"
  case "$2" in
    ok)       printf '#!/bin/sh\ncase "$1" in --start-server|--zero-stats) exit 0;; --show-stats) cat %s; exit 0;; esac\nexit 0\n' "$HERE/fixtures/sccache-show-stats-0.17.0.txt" > "$1/sccache" ;;
    drifted)  printf '#!/bin/sh\ncase "$1" in --start-server|--zero-stats) exit 0;; --show-stats) echo "Requests          772"; echo "Hits              765"; exit 0;; esac\nexit 0\n' > "$1/sccache" ;;
    silent)   printf '#!/bin/sh\ncase "$1" in --start-server|--zero-stats) exit 0;; --show-stats) exit 0;; esac\nexit 0\n' > "$1/sccache" ;;
    deadstart) printf '#!/bin/sh\ncase "$1" in --start-server) echo "sccache: error: Failed to create S3 cache"; echo "Source:"; echo "  dispatch failure"; exit 1;; esac\nexit 0\n' > "$1/sccache" ;;
  esac
  chmod +x "$1"/*
}
probe_run() {
  # Compose exactly what CI runs, then run it with the fakes. stderr is dropped
  # because run-check.sh also writes CACHE-DNS-* markers there, and folding
  # those into the command would test a string nobody executes.
  #
  # The prefix is stripped from the FIRST LINE ONLY, and every other line is
  # kept. The composed command is ~58 lines; an `s/.../p` here matched just the
  # one line carrying the prefix and silently handed bash a truncated `if`,
  # which failed as a syntax error with exit 2 -- and the exit-status assertions
  # below then read that 2 as "the epilogue rewrote the status". A truncated
  # reading dressed as the failure it was looking for, caught only because the
  # cases assert on the marker text as well as the code.
  local dir="$1" cmd
  cmd=$(RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>/dev/null | sed '1s/^would run via hardened-run: //')
  ( cd "$dir" && PATH="$dir/bin:$PATH" RUSTC_WRAPPER=sccache bash -c "$cmd" ) 2>&1
}

probe_tmp=$(mktemp -d); trap 'rm -rf "$probe_tmp"' EXIT

probe_fakes "$probe_tmp/bin" ok 0
out=$(probe_run "$probe_tmp"); rc=$?
grep -q 'CACHE-STATS clippy — requests=772 .*hits=765 misses=7' <<<"$out" \
  && ok "a healthy cache reports its hits and misses by name" \
  || bad "no usable CACHE-STATS line from a healthy cache: $out"
grep -q 'avg-read-hit=0.167 s' <<<"$out" \
  && ok "the reading carries what a read COST, which is the NAS question" \
  || bad "CACHE-STATS omits the average read-hit time: $out"
grep -q 'CACHE-STATS-UNAVAILABLE' <<<"$out" \
  && bad "a healthy cache reported its reading as unavailable: $out" \
  || ok "a healthy cache does not also claim the reading is unavailable"
[ "$rc" -eq 0 ] && ok "the epilogue leaves a passing check's exit status alone" \
  || bad "the stats epilogue changed a passing check's exit status to $rc"

# The one that matters most: a check that FAILS must still report its cache
# reading, and must still report its own failure. An epilogue that swallowed
# either would be worse than no epilogue.
probe_fakes "$probe_tmp/bin" ok 1
out=$(probe_run "$probe_tmp"); rc=$?
[ "$rc" -eq 1 ] && ok "a failing check keeps its exit status through the epilogue" \
  || bad "the stats epilogue rewrote a failing check's exit status to $rc -- a FAIL would read as a PASS"
grep -q 'CACHE-STATS clippy' <<<"$out" \
  && ok "a failing check still reports its cache reading" \
  || bad "the reading is lost exactly when a check fails: $out"

# Format drift must be LOUD. sccache 0.17.0 is pinned in the ci-toolchain
# Dockerfile, but a pin is a fact about today; a bump that renames a label
# must not turn this reading silently into nothing, which is the defect the
# whole marker exists to remove.
probe_fakes "$probe_tmp/bin" drifted 0
out=$(probe_run "$probe_tmp")
grep -q 'CACHE-STATS-UNAVAILABLE' <<<"$out" \
  && ok "a renamed label is reported, not swallowed" \
  || bad "drifted stats output produced no marker at all -- silence reads as 'no cache reading needed': $out"
grep -q "'Cache hits'" <<<"$out" \
  && ok "the drift marker NAMES the labels it could not find" \
  || bad "drift marker does not say which labels went missing, so nobody can fix it: $out"

probe_fakes "$probe_tmp/bin" silent 0
out=$(probe_run "$probe_tmp")
grep -q 'CACHE-STATS-UNAVAILABLE' <<<"$out" \
  && ok "stats output that is empty is reported as unavailable" \
  || bad "empty stats output produced no marker: $out"

# And the complement: when sccache cannot START, there is no server to ask, so
# the run must carry CACHE-UNAVAILABLE and NOT a stats line. A CACHE-STATS of
# all zeros here would be the arc's signature defect committed inside the fix
# for it -- a reading that cannot tell "read nothing" from "never ran".
probe_fakes "$probe_tmp/bin" deadstart 0
out=$(probe_run "$probe_tmp")
grep -q 'CACHE-UNAVAILABLE clippy' <<<"$out" \
  && ok "a cache that cannot start still says so" \
  || bad "dead sccache produced no CACHE-UNAVAILABLE marker: $out"
grep -q 'CACHE-STATS' <<<"$out" \
  && bad "a cache that never started reported cache statistics -- 'read nothing' and 'never ran' are indistinguishable again: $out" \
  || ok "no stats are claimed for a cache that never started"

rm -rf "$probe_tmp"; trap - EXIT

# An unknown check name must fail loudly, not silently pass.
"$SCRIPT" no-such-check >/dev/null 2>&1
[ $? -ne 0 ] && ok "unknown check name is refused" || bad "unknown check passed"

# FIX ROUND 1 ADDENDUM: a missing check-name argument is a refusal (93), not
# an ordinary exit 1 -- same defect, same fix, as hardened-run.sh's
# HARDENED_RUN_IMAGE case and cache-env.sh's missing-bucket/S3_ENDPOINT cases.
out=$("$SCRIPT" 2>&1); rc=$?
[ "$rc" -eq 93 ] && ok "missing check-name argument exits 93, not a bare 1" \
  || bad "missing check-name argument did not exit 93 (rc=$rc): $out"

# FIX ROUND 1, Major 1: exit codes 89-99 are hardened-run.sh's reserved
# "could not run safely" band. A refusal there is not a statement about the
# check, so it must NEVER be downgraded by state: reporting -- nine of the
# ten real checks are reporting, including all four compiling ones, i.e.
# every check that can ever reach hardened-run.sh at all. Tested against
# clippy (compiling, reporting) with both documented codes (90-93) and one
# deliberately undocumented mid-band code (95), plus the band's own edges
# (89, 99), to prove the whole range is covered, not just the codes named
# in a comment somewhere.
for code in 89 90 91 92 93 95 97 99; do
  out=$(RUN_CHECK_FORCE_RC=$code "$SCRIPT" clippy 2>&1); rc=$?
  [ $rc -ne 0 ] && ok "exit $code on a reporting check still fails the job" \
    || bad "exit $code was swallowed by reporting state -- read as a lint result"
  grep -qi "report-only" <<<"$out" \
    && bad "exit $code was reported as an ordinary report-only result: $out" \
    || ok "exit $code is not reported as an ordinary check result"
done

# The band has edges: a code just outside 89-99 on either side must still go
# through the ordinary reporting/blocking logic, not be swallowed as a
# refusal by an over-wide range check.
for code in 88 100; do
  out=$(RUN_CHECK_FORCE_RC=$code "$SCRIPT" clippy 2>&1); rc=$?
  [ $rc -eq 0 ] && ok "exit $code (outside the band) still follows reporting state" \
    || bad "exit $code (outside the band) was treated as a refusal (rc=$rc): $out"
  grep -qi "report-only" <<<"$out" && ok "exit $code is reported as an ordinary result" \
    || bad "exit $code (outside the band) lost its ordinary report-only reporting: $out"
done

# The reviewer's own reproduction: a refusal must fail even a *blocking*
# check that was told, via the test hooks, to report PASS. `[ $rc -ne 0 ]`
# alone cannot tell this apart from an ORDINARY blocking failure -- a
# blocking check that fails also exits non-zero, so disabling the whole
# refusal-band check would still leave this "ok" (a real regression the
# review caught by mutation). Must also assert the REFUSE-specific message,
# which only the refusal branch prints.
out=$(RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=90 "$SCRIPT" clippy 2>&1); rc=$?
[ $rc -ne 0 ] && grep -q "^REFUSE clippy" <<<"$out" \
  && ok "a refusal fails a blocking check too, reported as REFUSE not an ordinary blocking FAIL" \
  || bad "a refusal on a blocking check either passed (rc=$rc) or wasn't reported as REFUSE (indistinguishable from an ordinary blocking FAIL): $out"

# FIX ROUND 1, Major 2: run-check.sh's own test hooks need the same CI-leak
# guard hardened-run.sh already has (same three markers, same exit code) --
# otherwise a leaked RUN_CHECK_FORCE_RC/RUN_CHECK_FORCE_STATE/RUN_CHECK_DRY
# silently defeats every check this script runs.
out=$(FORGEJO_ACTIONS=true RUN_CHECK_FORCE_STATE=blocking RUN_CHECK_FORCE_RC=0 \
      "$SCRIPT" clippy 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses leaked RUN_CHECK_FORCE_STATE/RUN_CHECK_FORCE_RC under CI" \
  || bad "did not refuse under CI (rc=$rc) -- the reviewer's PASS-without-running reproduction: $out"

out=$(CI=true RUN_CHECK_DRY=1 "$SCRIPT" clippy 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses leaked RUN_CHECK_DRY under CI" \
  || bad "did not refuse leaked RUN_CHECK_DRY under CI (rc=$rc): $out"
grep -q "RUN_CHECK_DRY" <<<"$out" && ok "names RUN_CHECK_DRY as the offender" \
  || bad "did not name the offending variable: $out"

out=$(GITHUB_ACTIONS=true RUN_CHECK_FORCE_RC=0 "$SCRIPT" clippy 2>&1); rc=$?
[ "$rc" -eq 92 ] && ok "refuses leaked RUN_CHECK_FORCE_RC alone under CI" \
  || bad "did not refuse leaked RUN_CHECK_FORCE_RC under CI (rc=$rc): $out"
grep -q "RUN_CHECK_FORCE_RC" <<<"$out" && ok "names RUN_CHECK_FORCE_RC as the offender" \
  || bad "did not name the offending variable: $out"

# MINOR: a lookup that hangs must not hang run-check.sh forever -- a timeout
# is a refusal, not a pass. $SCRIPT (not a hardcoded path -- this must honour
# RUN_CHECK the same as every other case here, or a mutation to the timeout
# logic itself would go untested) is symlinked next to a stub lookup-check.py
# that never returns, so the timeout WRAPPER is what's under test, not
# lookup-check.py's own correctness.
TIMEOUT_DIR="${TMPDIR:-/tmp}/run-check-timeout-test.$$"
mkdir -p "$TIMEOUT_DIR"
ln -sf "$SCRIPT" "$TIMEOUT_DIR/run-check.sh"
ln -sf "$HERE/fixtures/lookup-check-hang.py" "$TIMEOUT_DIR/lookup-check.py"
start=$(date +%s)
out=$(RUN_CHECK_LOOKUP_TIMEOUT=1 "$TIMEOUT_DIR/run-check.sh" clippy 2>&1); rc=$?
elapsed=$(( $(date +%s) - start ))
rm -rf "$TIMEOUT_DIR"
[ "$rc" -ne 0 ] && ok "a hung lookup fails the job, not a silent pass" \
  || bad "a hung lookup exited 0"
[ "$elapsed" -lt 10 ] && ok "the hang is bounded (took ${elapsed}s, not left to run 30s)" \
  || bad "run-check.sh waited out the full hang (${elapsed}s) -- no timeout took effect"
grep -qi "timed out\|timeout" <<<"$out" && ok "names it as a timeout, not a generic failure" \
  || bad "timeout was not named: $out"

# FIX ROUND 1 (Task 5's fix round): a capped check must forward the seven
# cache/credential variable NAMES to hardened-run.sh via --forward-env; an
# uncapped check must never invoke hardened-run.sh at all. Proven against a
# stub hardened-run.sh's own recorded argv -- what run-check.sh actually
# calls it with -- using the same symlink substitution the timeout case
# above uses for lookup-check.py, not a claim about run-check.sh's source.
#
# Uses a synthetic checks.yaml (fixtures/checks-forward-test.yaml), not the
# real one: the real checks' commands (`cargo deny check`, `just clippy`, ...)
# are real, network-touching tools on this host -- an earlier version of
# this test called the real `cargo-deny` for its "uncapped" case and it
# spent minutes fetching an advisory-db over git before being killed. This
# test only needs to know which path run-check.sh takes, not whether a real
# check tool passes, and "true" as both fixture commands makes the uncapped
# path's real `bash -c "true"` instant and harmless either way.
FORWARD_DIR="${TMPDIR:-/tmp}/run-check-forward-test.$$"
mkdir -p "$FORWARD_DIR"
ln -sf "$SCRIPT" "$FORWARD_DIR/run-check.sh"
ln -sf "$HERE/../lookup-check.py" "$FORWARD_DIR/lookup-check.py"
ln -sf "$HERE/fixtures/hardened-run-stub.sh" "$FORWARD_DIR/hardened-run.sh"
FAKE_CHECKS="$HERE/fixtures/checks-forward-test.yaml"

ARGS_FILE="$FORWARD_DIR/hardened-run-args"
CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  "$FORWARD_DIR/run-check.sh" fake-capped >/dev/null 2>&1
# DERIVED FROM cache-env.sh, not typed out again. Until 2026-09-19 this loop
# held a hand-written list of seven names -- a THIRD copy of a set already
# written twice (cache-env.sh's echoes, run-check.sh's CACHE_FORWARD_VARS).
# Three copies cannot disagree usefully: when SCCACHE_REGION was added to the
# first two, this test kept passing, because a membership check over its own
# stale list is satisfied by any superset. It asserted that seven names it
# already knew about were present, which was never the question.
#
# So the expected set is now COMPUTED: whatever cache-env.sh actually prints,
# plus the two AWS credentials it deliberately does not print (they hold
# secrets and are supplied by the caller's environment). Both directions are
# checked -- a name emitted but not forwarded is silently ignored by the
# process that needs it, and a name forwarded but never emitted is a stale
# entry nobody will remove.
#
# CACHE_KEY_PREFIX is set for the derivation (2026-09-19) so the computed set
# covers cache-env.sh's FULL emit surface. It prints SCCACHE_S3_KEY_PREFIX only
# when a prefix is given, so deriving from a default invocation would miss that
# name entirely -- and then the stale-entry direction below would report the
# correctly-forwarded variable as an error, while the missing-forward direction
# would never think to ask for it. A derivation is only as good as the inputs it
# exercises: driving the source with its default arguments computes a set that
# happens to match what the default produces, which is not the same as the set
# the code can produce.
EXPECTED_FWD="$(S3_ENDPOINT=https://fixture.example:9000 \
  CACHE_KEY_PREFIX=fixtureprefix \
  "$HERE/../cache-env.sh" fixture-bucket | cut -d= -f1)
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY"

# Positive control on the derivation itself: the prefix name must actually be in
# there. Without this line, a cache-env.sh that silently stopped emitting the
# prefix would shrink the expected set and every assertion below would keep
# passing over the smaller one.
grep -qx SCCACHE_S3_KEY_PREFIX <<<"$EXPECTED_FWD" \
  && ok "the derivation exercised the prefix path (SCCACHE_S3_KEY_PREFIX present)" \
  || bad "CACHE_KEY_PREFIX was set but cache-env.sh emitted no SCCACHE_S3_KEY_PREFIX -- the derivation is not covering the full emit surface"

n_expected=$(grep -c . <<<"$EXPECTED_FWD")
[ "$n_expected" -ge 9 ] \
  && ok "derived $n_expected expected forward names from cache-env.sh itself" \
  || bad "cache-env.sh yielded only $n_expected names -- the derivation failed, so every assertion below would pass vacuously"

while IFS= read -r v; do
  [ -z "$v" ] && continue
  grep -qx -- "--forward-env" "$ARGS_FILE" 2>/dev/null && grep -qx "$v" "$ARGS_FILE" 2>/dev/null \
    && ok "forwards $v to hardened-run.sh on the capped path" \
    || bad "did not forward $v to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"
done <<<"$EXPECTED_FWD"

# The other direction: nothing is forwarded that cache-env.sh never emits.
ACTUAL_FWD="$(grep -A1 -x -- "--forward-env" "$ARGS_FILE" 2>/dev/null | grep -vx -e '--forward-env' -e '--' | sort -u)"
EXTRA="$(comm -13 <(sort -u <<<"$EXPECTED_FWD") <(printf '%s\n' "$ACTUAL_FWD"))"
[ -z "$EXTRA" ] \
  && ok "forwards nothing cache-env.sh does not emit (no stale entries)" \
  || bad "forwards name(s) cache-env.sh never emits: $(tr '\n' ' ' <<<"$EXTRA")"

# TASK 7B: the capped container starts empty -- hardened-run.sh puts nothing
# in it on its own -- so every capped check must be given --source/--workdir,
# or its command runs against nothing and fails looking exactly like a real
# bug in the code under test.
grep -qx -- "--source" "$ARGS_FILE" 2>/dev/null \
  && ok "passes --source to hardened-run.sh on the capped path" \
  || bad "did not pass --source to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"
grep -qx -- "--workdir" "$ARGS_FILE" 2>/dev/null && grep -qx "/src" "$ARGS_FILE" 2>/dev/null \
  && ok "passes --workdir /src to hardened-run.sh on the capped path" \
  || bad "did not pass --workdir /src to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"

# FIX ROUND 1: hardened-run.sh names no project, so it does not know
# "Cargo.toml" is the right file to look for -- that knowledge is
# run-check.sh's own (this IS a cargo workspace), passed through explicitly.
grep -qx -- "--verify-file" "$ARGS_FILE" 2>/dev/null && grep -qx "Cargo.toml" "$ARGS_FILE" 2>/dev/null \
  && ok "passes --verify-file Cargo.toml to hardened-run.sh on the capped path" \
  || bad "did not pass --verify-file Cargo.toml to hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"

# --- the cache host is resolved HERE and carried across as /etc/hosts -------
# Run 604 measured that the capped container cannot resolve a homelab name
# (its daemon falls back to Google's resolvers) while the job container can.
# So run-check.sh looks the host up where the lookup works and passes the
# answer as --add-host. Three cases, because the interesting property is not
# "a flag appears" but "it appears exactly when it should".
#
# `localhost` and `.invalid` are chosen so these assertions mean the same
# thing on any machine: localhost always resolves to 127.0.0.1, and RFC 2606
# guarantees .invalid never resolves at all. A real hostname here would make
# the suite's verdict depend on the DNS of whoever ran it -- which is the
# defect run 580 found in test-assert-toolchain.sh, one file over.
rm -f "$ARGS_FILE"
CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  SCCACHE_ENDPOINT=https://localhost:9000 \
  "$FORWARD_DIR/run-check.sh" fake-capped >/dev/null 2>&1
if grep -qx -- "--add-host" "$ARGS_FILE" 2>/dev/null; then
  ok "a resolvable cache host produces --add-host"
  grep -qx "localhost:127.0.0.1" "$ARGS_FILE" 2>/dev/null \
    && ok "and the mapping carries the address the job container resolved, not a typed one" \
    || bad "--add-host was passed with the wrong value: $(grep -A1 -x -- '--add-host' "$ARGS_FILE" 2>/dev/null)"
else
  bad "a resolvable cache host did not produce --add-host: $(cat "$ARGS_FILE" 2>/dev/null)"
fi

# A host that cannot resolve must DEGRADE, not refuse: the check still runs,
# uncached, and says so in the same greppable marker every other cache outage
# uses. Refusing here would convert a cache problem into a red check, which
# run-check.sh's own CACHE_PROBE block already settles in the other direction.
rm -f "$ARGS_FILE"
out=$(CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  SCCACHE_ENDPOINT=https://no-such-host.invalid:9000 \
  "$FORWARD_DIR/run-check.sh" fake-capped 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "an unresolvable cache host still lets the check run (degrade, not refuse)" \
  || bad "an unresolvable cache host turned into a failure (rc=$rc): $out"
grep -qx -- "--add-host" "$ARGS_FILE" 2>/dev/null \
  && bad "passed --add-host for a host that does not resolve: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "and passes no --add-host rather than a mapping to nothing"
grep -q "CACHE-UNAVAILABLE.*could not resolve" <<<"$out" \
  && ok "and names the resolution failure in the marker run-all-checks.sh collects" \
  || bad "a resolution failure was silent -- the one thing this must not be: $out"

# THE NEGATIVE CONTROL, and it needs `env -u`: SCCACHE_ENDPOINT is exactly the
# kind of variable a developer has exported in their own shell, and an ambient
# value would make this case pass while testing nothing. That happened on this
# machine with RUSTC_WRAPPER on 2026-09-19 and cost a real control.
rm -f "$ARGS_FILE"
env -u SCCACHE_ENDPOINT CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  "$FORWARD_DIR/run-check.sh" fake-capped >/dev/null 2>&1
grep -qx -- "--add-host" "$ARGS_FILE" 2>/dev/null \
  && bad "passed --add-host with no cache configured at all: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "no cache configured means no --add-host -- the flag is conditional, not decorative"

# ---------------------------------------------------------------------------
# The DERIVED cluster resolver (--dns). Run 608 measured that a container on
# the inner daemon's default bridge honours --dns and can reach the cluster
# resolver from there; these assert the derivation that decides WHICH address,
# which is the half that can go wrong silently.
#
# Every case hands the script a FIXTURE resolv.conf. Reading the host's real
# /etc/resolv.conf here would make the verdict depend on the machine running
# the suite -- that is run 580's defect, where test-assert-toolchain.sh passed
# on Fedora and failed on Debian for reasons that had nothing to do with the
# code under test.
RESOLV_DIR="${TMPDIR:-/tmp}/run-check-resolv.$$"
mkdir -p "$RESOLV_DIR"
mkresolv() { printf '%s\n' 'nameserver 127.0.0.11' "$2" > "$RESOLV_DIR/$1"; }
mkresolv good     '# ExtServers: [10.96.0.10]'
mkresolv edge     '# ExtServers: [10.111.255.254]'
mkresolv public   '# ExtServers: [8.8.8.8]'
mkresolv two      '# ExtServers: [10.96.0.10,10.96.0.11]'
mkresolv nearmiss '# ExtServers: [10.95.0.10]'
mkresolv garbage  '# ExtServers: [host(10.96.0.10)]'
printf '%s\n' 'nameserver 1.1.1.1' > "$RESOLV_DIR/absent"

dnsrun() {  # $1 = fixture name; leaves the captured args in $ARGS_FILE, output in $out
  rm -f "$ARGS_FILE"
  out=$(CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
        RUN_CHECK_RESOLV_CONF="$RESOLV_DIR/$1" \
        SCCACHE_ENDPOINT=https://localhost:9000 \
        "$FORWARD_DIR/run-check.sh" fake-capped 2>&1); rc=$?
}

dnsrun good
if grep -qx -- "--dns" "$ARGS_FILE" 2>/dev/null; then
  ok "a single in-range ExtServers address produces --dns"
  grep -qx "10.96.0.10" "$ARGS_FILE" 2>/dev/null \
    && ok "and --dns carries the address DERIVED from the file, not a typed one" \
    || bad "--dns was passed with the wrong value: $(cat "$ARGS_FILE" 2>/dev/null)"
else
  bad "an in-range ExtServers address produced no --dns: $(cat "$ARGS_FILE" 2>/dev/null)"
fi
[ "$rc" -eq 0 ] && ok "and the check still runs" || bad "deriving a resolver failed the check (rc=$rc): $out"
# The POSITIVE reading. Without this line, a successful derivation is silent,
# and the only evidence it happened is the absence of a fallback marker --
# which a deleted or short-circuited block also produces. Success has to
# announce itself or the log cannot tell the two apart.
grep -q "CACHE-DNS-DERIVED.*10\.96\.0\.10" <<<"$out" \
  && ok "a successful derivation SAYS so, naming the address it derived" \
  || bad "the derivation succeeded silently -- a deleted block would look identical: $out"

# The top of 10.96.0.0/12. A range check written as a prefix match on "10.96."
# would reject this and nobody would notice until the cluster used it.
dnsrun edge
grep -qx "10.111.255.254" "$ARGS_FILE" 2>/dev/null \
  && ok "the top of 10.96.0.0/12 is accepted, so the range is a range and not a prefix" \
  || bad "10.111.255.254 was rejected: $out"

# THE SECURITY CASE. A runner reconfigured to forward to a public resolver must
# not have that address derived into the sandbox as "the cluster resolver" --
# every lookup in every capped check would quietly go off-site.
dnsrun public
grep -qx -- "--dns" "$ARGS_FILE" 2>/dev/null \
  && bad "a PUBLIC resolver was handed to the sandbox as the cluster resolver: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "a public resolver in ExtServers is refused, not derived"
grep -q "CACHE-DNS-FALLBACK.*not an IPv4 address in the cluster service range" <<<"$out" \
  && ok "and the refusal says so in the marker rather than passing silently" \
  || bad "a refused resolver was silent: $out"
[ "$rc" -eq 0 ] && ok "and the check still runs uncached rather than going red" \
  || bad "a refused resolver turned into a failure (rc=$rc): $out"

# One below the range. Distinct from the public case: this one is private
# space, so a check that only asked "is it an RFC1918 address" would pass it.
dnsrun nearmiss
grep -qx -- "--dns" "$ARGS_FILE" 2>/dev/null \
  && bad "10.95.0.10 is outside 10.96.0.0/12 and was still derived: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "a private address just below the service range is refused too"

dnsrun two
grep -qx -- "--dns" "$ARGS_FILE" 2>/dev/null \
  && bad "picked one of two ExtServers: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "two servers in ExtServers means no --dns -- it refuses rather than guessing"
grep -q "CACHE-DNS-FALLBACK.*lists 2 servers" <<<"$out" \
  && ok "and the marker names how many it found" || bad "the two-server refusal did not say so: $out"

# Docker has written ExtServers in other shapes in other versions. Anything
# that is not a bare dotted quad is refused rather than string-mangled into one.
dnsrun garbage
grep -qx -- "--dns" "$ARGS_FILE" 2>/dev/null \
  && bad "a non-address ExtServers entry was turned into a --dns value: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "an ExtServers entry that is not a bare address is refused"

# THE NEGATIVE CONTROL. Without it every assertion above would still pass if
# the address were hardcoded in run-check.sh.
dnsrun absent
grep -qx -- "--dns" "$ARGS_FILE" 2>/dev/null \
  && bad "passed --dns with no ExtServers line at all -- the address is hardcoded somewhere: $(cat "$ARGS_FILE" 2>/dev/null)" \
  || ok "no ExtServers line means no --dns -- the value comes from the file, nowhere else"
grep -q "CACHE-DNS-DERIVED" <<<"$out" \
  && bad "announced a derived resolver when there was no ExtServers line at all: $out" \
  || ok "and claims no derivation it did not make"
grep -q "CACHE-DNS-FALLBACK.*no '# ExtServers:' line" <<<"$out" \
  && ok "and the missing line is named in the marker" || bad "a missing ExtServers line was silent: $out"

# Both routes are kept on purpose: they fail independently. The good fixture
# resolves `localhost`, so this run must carry BOTH.
dnsrun good
grep -qx -- "--add-host" "$ARGS_FILE" 2>/dev/null \
  && ok "--dns does not displace --add-host: both routes are passed together" \
  || bad "--add-host disappeared once --dns was derived: $(cat "$ARGS_FILE" 2>/dev/null)"
rm -rf "$RESOLV_DIR"

rm -f "$ARGS_FILE"
out=$(CHECKS_FILE="$FAKE_CHECKS" STUB_HARDENED_RUN_ARGS_FILE="$ARGS_FILE" \
  "$FORWARD_DIR/run-check.sh" fake-uncapped 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "the uncapped fixture check still passes" || bad "fake-uncapped failed (rc=$rc): $out"
[ ! -e "$ARGS_FILE" ] && ok "an uncapped check never invokes hardened-run.sh at all" \
  || bad "fake-uncapped still called hardened-run.sh: $(cat "$ARGS_FILE" 2>/dev/null)"
rm -rf "$FORWARD_DIR"

# ---------------------------------------------------------------------------
# Task 7A: a check whose declared `tools:` are missing refuses (97) before
# running anything, instead of running and reporting whatever the missing
# tool's own failure happens to look like (measured 2026-09-18:
# `check-lockfile.sh` reported PASS with jq missing).
# ---------------------------------------------------------------------------
TOOLS_FIXTURE="$HERE/fixtures/checks-tools-test.yaml"

# A self-contained PATH: only what run-check.sh itself needs to execute at
# all (bash for its own shebang, dirname/timeout/cut/python3 for its own
# body) -- never a PATH="" or similarly total restriction, which would break
# bash's own execution and produce a 127 from the wrong thing, proving
# nothing. "cargo" is deliberately absent from it -- not uninstalled
# anywhere on this machine, just left out of this self-contained PATH -- so
# the ONLY thing missing, from run-check.sh's point of view, is the
# declared tool under test.
TOOLS_BIN="${TMPDIR:-/tmp}/run-check-tools-test.$$"
mkdir -p "$TOOLS_BIN"
for b in bash dirname timeout cut python3; do
  ln -sf "$(command -v "$b")" "$TOOLS_BIN/$b"
done

# Step 4(a): declared tool absent exits 97 BEFORE running anything -- proven
# by the check's own distinctive output never appearing, not merely by the
# exit code (a check that ran and happened to also exit 97 would pass a
# bare `rc -eq 97` just as well).
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$TOOLS_BIN" "$SCRIPT" fake-missing-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "declared tool absent: exits 97" \
  || bad "declared tool absent: expected rc=97, got rc=$rc: $out"
grep -q "cargo" <<<"$out" && ok "declared tool absent: names the missing tool" \
  || bad "declared tool absent: message does not name cargo: $out"
grep -q "SHOULD_NOT_RUN_MARKER" <<<"$out" \
  && bad "declared tool absent: the check's command ran anyway: $out" \
  || ok "declared tool absent: the command never ran"

# Every missing tool is reported, not just the first -- reporting only one
# per run is how a four-tool gap takes four CI runs to discover, and each
# of those runs costs a human a read.
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$TOOLS_BIN" "$SCRIPT" fake-missing-multi 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "multiple declared tools absent: exits 97" \
  || bad "multiple declared tools absent: expected rc=97, got rc=$rc: $out"
grep -q "cargo" <<<"$out" && grep -q "made-up-tool-zzz" <<<"$out" \
  && ok "multiple declared tools absent: names all of them, not just the first" \
  || bad "multiple declared tools absent: did not name both missing tools: $out"

# Step 4(c): a state: reporting check that refuses with 97 is NOT printed as
# an ordinary report-only FAIL -- reuse the same declared-missing-tool case
# (state: reporting) and assert both the non-zero exit AND the absence of
# report-only wording, since `rc -ne 0` alone would not catch a regression
# that kept the refusal but mislabelled it.
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$TOOLS_BIN" "$SCRIPT" fake-missing-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "reporting check's tool refusal is not downgraded to 0" \
  || bad "reporting check's tool refusal was downgraded (rc=$rc): $out"
grep -qi "report-only" <<<"$out" \
  && bad "reporting check's tool refusal was printed as an ordinary report-only FAIL: $out" \
  || ok "reporting check's tool refusal is not printed as report-only"

rm -rf "$TOOLS_BIN"

# ---------------------------------------------------------------------------
# The tools gate asks WHERE THE COMMAND RUNS (2026-09-19, homelab-br5.16).
#
# Until today the gate ran `command -v` in the job container for every check,
# while capped checks went on to run their command inside hardened-run.sh's
# container -- a different image. So a capped check's tools were demanded on a
# filesystem the command would never touch. The gate now splits: uncapped
# checks are asked here (every assertion above still passes unchanged, which is
# how we know the uncapped half did not move), capped checks are asked inside
# the sandbox by a probe prefixed to the command.
#
# The three cases below are the composition; the two after them EXECUTE the
# composed string, because a probe that is composed correctly is not a probe
# that refuses correctly.
# ---------------------------------------------------------------------------
out=$(CHECKS_FILE="$TOOLS_FIXTURE" RUN_CHECK_DRY=1 "$SCRIPT" fake-capped-missing-tool 2>&1)
grep -q "made-up-tool-zzz" <<<"$out" \
  && ok "capped: the probe names the declared tool" \
  || bad "capped: dry run does not carry a probe for the declared tool: $out"
grep -q "inside the sandbox" <<<"$out" \
  && ok "capped: the probe says WHICH environment it is asking about" \
  || bad "capped: the probe does not name the environment: $out"
out=$(CHECKS_FILE="$TOOLS_FIXTURE" RUN_CHECK_DRY=1 "$SCRIPT" fake-present-tool 2>&1)
grep -q "command -v" <<<"$out" \
  && bad "uncapped: a sandbox probe was prefixed to a check that runs in the job container: $out" \
  || ok "uncapped: no sandbox probe — it is gated here, where it runs"

# Executed, not just composed. hardened-run-exec-stub.sh runs the string
# run-check.sh hands the sandbox, so the probe's own shell decides the exit
# code. Safe because this fixture's commands are `echo`s: pointing this at the
# real checks.yaml would hand it `just clippy` and start a Rust build on the
# machine running the tests.
#
# No PATH restriction here, deliberately. "made-up-tool-zzz" is absent from
# every PATH by construction, and under a crippled PATH the shell fails for
# reasons of its own and returns an exit code that has nothing to do with the
# probe. (This said "runs under `bash -lc`, which sources login profiles"
# until later the same day: the `-l` is gone, because /etc/profile ASSIGNS
# PATH and that cost run 567 a full CI cycle. The observation that login
# profiles mess with PATH was right here in the file the whole time, one
# question short of the bug.)
# Measured 2026-09-19: a first version of this test returned 101 for BOTH the
# missing-tool and present-tool cases, from /usr/libexec/grepconf.sh, and could
# not distinguish them at all.
#
# The directory is built from $SCRIPT's OWN directory, not from "$HERE/..".
# First version of this block symlinked "$HERE/../run-check.sh" -- the real
# script -- so it ignored $SCRIPT entirely and every assertion below tested the
# unmutated original no matter what was under test. Found 2026-09-19 by
# mutation: removing the split and disarming the probe both left this suite
# green. A test that cannot be pointed at the code under test is not a test of
# it, which is this suite's own subject matter turned on itself.
EXEC_DIR="${TMPDIR:-/tmp}/run-check-capped-exec.$$"
mkdir -p "$EXEC_DIR"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT")" && pwd)"
for f in "$SCRIPT_DIR"/*; do ln -sf "$f" "$EXEC_DIR/$(basename "$f")"; done
# Overrides the hardened-run.sh just linked in: last write wins, and this one
# executes what it is handed instead of starting a container.
ln -sf "$HERE/fixtures/hardened-run-exec-stub.sh" "$EXEC_DIR/hardened-run.sh"

# Guard against the failure above ever returning silently: the script this
# block is about to run must be the one under test.
if [ "$(readlink -f "$EXEC_DIR/run-check.sh")" = "$(readlink -f "$SCRIPT")" ]; then
  ok "capped exec harness points at the script under test"
else
  bad "capped exec harness points at $(readlink -f "$EXEC_DIR/run-check.sh"), not $(readlink -f "$SCRIPT") — every capped assertion below would be void"
fi

out=$(CHECKS_FILE="$TOOLS_FIXTURE" "$EXEC_DIR/run-check.sh" fake-capped-missing-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "capped, tool missing in the sandbox: exits 97" \
  || bad "capped, tool missing: expected rc=97, got rc=$rc: $out"
grep -q "SHOULD_NOT_RUN_CAPPED" <<<"$out" \
  && bad "capped, tool missing: the check's command ran anyway: $out" \
  || ok "capped, tool missing: the command never ran"
grep -q "inside the sandbox" <<<"$out" \
  && ok "capped, tool missing: says which environment lacked it" \
  || bad "capped, tool missing: does not say where it looked: $out"

# The control. Without it, a probe hardwired to refuse would pass everything
# above -- and a gate that refuses everything is as useless as one that refuses
# nothing.
out=$(CHECKS_FILE="$TOOLS_FIXTURE" "$EXEC_DIR/run-check.sh" fake-capped-present-tool 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "capped, tool present: the probe lets the command through" \
  || bad "capped, tool present: expected rc=0, got rc=$rc: $out"
grep -q "CAPPED_COMMAND_RAN" <<<"$out" \
  && ok "capped, tool present: the command actually ran" \
  || bad "capped, tool present: the command did not run: $out"

# EVERY missing tool, not just the first. The uncapped gate has always done
# this; the capped probe short-circuited until run 539 showed what that costs
# -- one missing tool discovered per CI run, each a queue cycle. The fixture
# declares a PRESENT tool first and two absent ones after it, so "names both"
# is distinguishable from "names the first miss" AND from "stops at the first
# entry" -- a single-missing-tool fixture can tell none of those apart, which
# is how the short-circuit survived this suite in the first place.
out=$(CHECKS_FILE="$TOOLS_FIXTURE" "$EXEC_DIR/run-check.sh" fake-capped-missing-multi 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "capped, two tools missing: exits 97" \
  || bad "capped, two tools missing: expected rc=97, got rc=$rc: $out"
if grep -q "made-up-tool-zzz" <<<"$out" && grep -q "made-up-tool-yyy" <<<"$out"; then
  ok "capped, two tools missing: names BOTH, not just the first"
else
  bad "capped, two tools missing: named only some of them — the probe is still short-circuiting: $out"
fi
grep -q "SHOULD_NOT_RUN_CAPPED_MULTI" <<<"$out" \
  && bad "capped, two tools missing: the check's command ran anyway: $out" \
  || ok "capped, two tools missing: the command never ran"

# THE CACHE PROBE, EXECUTED AGAINST THE SHAPE THAT DEFEATED IT (run 576).
#
# Everything above about the probe asserts that a STRING is present in the
# composed command. Presence was never the question. Run 576 carried the probe,
# ran it, emitted the marker on all five capped checks -- and every marker read
# `CACHE-UNAVAILABLE clippy — sccache: Starting the server...`, because the
# probe took the FIRST non-blank line and sccache prints a status banner before
# it prints a cause. The cache's actual reason for failing was discarded, so the
# run could not be diagnosed at all. Five green assertions above, and the guard
# was useless.
#
# So this runs the real probe with a real sccache on PATH that reproduces the
# banner-then-error shape, and requires the CAUSE line specifically. A fixture
# that emits its error on line 1 cannot fail for this bug, which is exactly why
# the old one never did.
SCC_DIR="${TMPDIR:-/tmp}/run-check-sccache.$$"
mkdir -p "$SCC_DIR"
cat > "$SCC_DIR/sccache" <<'FAKE'
#!/usr/bin/env bash
# The two-line shape sccache really produces: status first, cause second.
echo "sccache: Starting the server..."
echo "sccache: error: Server startup failed: create s3 cache failed: ConfigInvalid"
exit 1
FAKE
chmod +x "$SCC_DIR/sccache"

out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$SCC_DIR:$PATH" RUSTC_WRAPPER=sccache \
        "$EXEC_DIR/run-check.sh" fake-capped-present-tool 2>&1); rc=$?
grep -q "CACHE-UNAVAILABLE.*ConfigInvalid" <<<"$out" \
  && ok "dead cache: the marker carries sccache's CAUSE, not just its banner" \
  || bad "dead cache: no marker names the cause -- this is run 576's defect, the cache cannot be diagnosed from the log: $out"
[ "$(grep -c 'CACHE-UNAVAILABLE' <<<"$out")" -ge 2 ] \
  && ok "dead cache: every line of sccache's output is emitted, none selected away" \
  || bad "dead cache: only one line survived, so a cause printed below a banner would be lost again: $out"
[ "$rc" -eq 0 ] && ok "dead cache: the check still succeeds -- an outage costs speed, not correctness" \
  || bad "dead cache: expected rc=0 (degrade), got rc=$rc -- a cache outage turned the run red: $out"
grep -q "CAPPED_COMMAND_RAN" <<<"$out" \
  && ok "dead cache: the command ran anyway, uncached" \
  || bad "dead cache: the command did not run: $out"

# The control. Without it every assertion above is satisfied by a probe wired to
# report a dead cache unconditionally, which would make the marker meaningless
# in the other direction -- a cache outage reported on every run, forever.
cat > "$SCC_DIR/sccache" <<'FAKE'
#!/usr/bin/env bash
echo "sccache: Starting the server..."
exit 0
FAKE
chmod +x "$SCC_DIR/sccache"
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$SCC_DIR:$PATH" RUSTC_WRAPPER=sccache \
        "$EXEC_DIR/run-check.sh" fake-capped-present-tool 2>&1); rc=$?
grep -q 'CACHE-UNAVAILABLE' <<<"$out" \
  && bad "live cache: a working sccache was still reported unavailable: $out" \
  || ok "live cache: no marker -- the probe distinguishes a dead cache from a live one"
[ "$rc" -eq 0 ] && ok "live cache: the check succeeds" \
  || bad "live cache: expected rc=0, got rc=$rc: $out"

# Run 606's REAL shape: a banner, an error, a Context block, the cause under
# `Source:`, then fifteen backtrace frames that say `<unknown>`. The cause sat
# TENTH in a 26-line block and the CI step tails 25 lines, so the one line that
# explains the outage is the one that gets trimmed. A fixture whose cause is on
# line 2 cannot catch that -- which is why this one reproduces the depth.
cat > "$SCC_DIR/sccache" <<'FAKE'
#!/usr/bin/env bash
echo "sccache: Starting the server..."
echo "sccache: error: Server startup failed: cache storage failed to read: Unexpected (temporary) at read => send http request"
echo "Context:"
echo "   url: https://oga2.tenfourty.site:8010/warpgate-sccache/.sccache_check"
echo "   called: http_util::Client::send"
echo "   service: s3"
echo "   path: .sccache_check"
echo "   range: 0-"
echo "Source:"
echo "   error sending request: certificate verify failed (self-signed certificate)"
echo "Backtrace:"
for i in $(seq 0 14); do printf '   %d: <unknown>\n' "$i"; done
exit 1
FAKE
chmod +x "$SCC_DIR/sccache"
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$SCC_DIR:$PATH" RUSTC_WRAPPER=sccache \
        "$EXEC_DIR/run-check.sh" fake-capped-present-tool 2>&1); rc=$?

first=$(grep -m1 'CACHE-UNAVAILABLE' <<<"$out")
grep -q 'CAUSE: .*certificate verify failed' <<<"$first" \
  && ok "deep cause: the FIRST marker line carries the cause, so a tailed log still says why" \
  || bad "deep cause: the first marker line was not the cause -- a 25-line tail loses it: $first"

# Match an emitted FRAME, not the substring: the suppression notice below
# quotes '<unknown>' itself, so a bare substring test matches the very line
# that proves the frames were dropped. It did, on first run.
grep -qE 'CACHE-UNAVAILABLE.*[0-9]+: <unknown>' <<<"$out" \
  && bad "deep cause: contentless '<unknown>' frames were emitted, pushing the cause out of a tail: $out" \
  || ok "deep cause: the '<unknown>' backtrace frames are not emitted"
grep -q '15 backtrace frames suppressed' <<<"$out" \
  && ok "deep cause: and the suppression is COUNTED, not silent" \
  || bad "deep cause: frames vanished without the log saying any had been dropped: $out"

# Nothing with content is discarded: the Context url and the banner are both
# still there. This is the assertion that keeps (a) a duplication and not a
# selection -- run 576's defect was selecting one line and losing the rest.
grep -q 'url: https://oga2' <<<"$out" \
  && ok "deep cause: every line with content is still emitted below the summary" \
  || bad "deep cause: the Context block was discarded -- this is run 576's defect again: $out"
[ "$rc" -eq 0 ] && ok "deep cause: the check still degrades rather than failing" \
  || bad "deep cause: rc=$rc"

# A backtrace with a REAL symbol must survive: the rule drops frames with no
# content, not backtraces.
cat > "$SCC_DIR/sccache" <<'FAKE'
#!/usr/bin/env bash
echo "sccache: error: Server startup failed: something"
echo "Backtrace:"
echo "   0: <unknown>"
echo "   1: sccache::server::start_server"
exit 1
FAKE
chmod +x "$SCC_DIR/sccache"
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$SCC_DIR:$PATH" RUSTC_WRAPPER=sccache \
        "$EXEC_DIR/run-check.sh" fake-capped-present-tool 2>&1)
grep -q 'sccache::server::start_server' <<<"$out" \
  && ok "a backtrace frame that names a real symbol is kept" \
  || bad "a symbolised frame was suppressed along with the empty ones: $out"

# No `Source:` section at all: the summary must SAY so rather than be absent,
# or a format change would silently remove the one line added for the reader.
cat > "$SCC_DIR/sccache" <<'FAKE'
#!/usr/bin/env bash
echo "sccache: error: Server startup failed: no source section here"
exit 1
FAKE
chmod +x "$SCC_DIR/sccache"
out=$(CHECKS_FILE="$TOOLS_FIXTURE" PATH="$SCC_DIR:$PATH" RUSTC_WRAPPER=sccache \
        "$EXEC_DIR/run-check.sh" fake-capped-present-tool 2>&1)
grep -q "CAUSE: sccache printed no 'Source:' section" <<<"$out" \
  && ok "with no Source: section the summary says so instead of going missing" \
  || bad "the summary line vanished when the format did not match: $out"
grep -q 'no source section here' <<<"$out" \
  && ok "and the output is still emitted in full" || bad "output lost: $out"


rm -rf "$SCC_DIR"
rm -rf "$EXEC_DIR"

# Step 4(b): a check whose command exits 127 with its declared tools present
# still exits 97 -- the backstop (Step 2), independent of Step 1. No PATH
# restriction needed: RUN_CHECK_FORCE_RC bypasses running the command
# entirely, so this proves the CONVERSION logic, not any particular tool's
# absence (Step 1 is itself skipped whenever RUN_CHECK_FORCE_RC is set --
# see run-check.sh's own comment on that guard).
out=$(CHECKS_FILE="$TOOLS_FIXTURE" RUN_CHECK_FORCE_RC=127 "$SCRIPT" fake-present-tool 2>&1); rc=$?
[ "$rc" -eq 97 ] && ok "command exits 127 with tools present: converted to 97" \
  || bad "command exits 127 with tools present: expected rc=97, got rc=$rc: $out"
grep -qi "command not found" <<<"$out" && ok "127-to-97 conversion names \"command not found\"" \
  || bad "127-to-97 conversion did not explain itself: $out"

# ---------------------------------------------------------------------------
# Fix round 1: 99 ("found nothing to examine") must flow through
# run-check.sh's whole-band handling unmolested -- not just proven
# generically via RUN_CHECK_FORCE_RC above (the "exit 97/99 on a reporting
# check still fails the job" loop earlier in this file), but end to end
# through the REAL check-lockfile.sh, genuinely finding zero lockfiles. A
# synthetic checks.yaml (generated here, not committed -- it embeds this
# checkout's own absolute path) whose command `cd`s into a FRESH empty
# directory, created at COMMAND-run time via an unescaped `$(mktemp -d)` in
# the command string, before invoking the real check-lockfile.sh by
# absolute path. This is the concrete scenario fix round 1 named: a check
# running before source is delivered into the capped container (Task 7B's
# gap today) looks exactly like this.
# ---------------------------------------------------------------------------
REAL_LOCKFILE="$HERE/../check-lockfile.sh"
LOCKFILE_INT_FIXTURE="${TMPDIR:-/tmp}/run-check-lockfile-integration.$$.yaml"
cat > "$LOCKFILE_INT_FIXTURE" <<EOF
upstream_tag: v0.28.6
checks:
  - name: fake-lockfile-empty
    upstream: lockfile.yml
    command: cd \$(mktemp -d) && $REAL_LOCKFILE
    compiles: false
    state: reporting
    tools: [jq, find]
EOF

out=$(CHECKS_FILE="$LOCKFILE_INT_FIXTURE" "$SCRIPT" fake-lockfile-empty 2>&1); rc=$?
[ "$rc" -eq 99 ] && ok "check-lockfile.sh's own 99 (nothing examined) reaches run-check.sh intact" \
  || bad "expected rc=99 end-to-end through the real check-lockfile.sh, got rc=$rc: $out"
grep -q "^REFUSE fake-lockfile-empty" <<<"$out" \
  && ok "reported as REFUSE, not as an ordinary result" \
  || bad "not reported as REFUSE: $out"
grep -qi "report-only" <<<"$out" \
  && bad "a 'nothing examined' refusal was printed as an ordinary report-only FAIL: $out" \
  || ok "a 'nothing examined' refusal is not printed as report-only"
rm -f "$LOCKFILE_INT_FIXTURE"

# TASK 8's MISSING LINK: does run-check.sh take a state from checks.yaml at
# all? Every blocking assertion above sets RUN_CHECK_FORCE_STATE, which is
# applied at run-check.sh:77 -- AFTER the lookup at :54 -- so all of them
# prove run-check.sh honours a state it is handed and none of them touch the
# YAML. Run 537 could not close the gap either: `lockfile` and `helm-lint`
# PASSED there, and a passing check prints the same line whether it is
# blocking or reporting. So until this case existed, nothing in the system
# demonstrated that promoting a check in checks.yaml changed anything.
#
# The fixture's two checks differ in exactly one line, `state:`. No forced
# state is set anywhere below. If the exit codes differ, the state read from
# the file is the only thing that can have made them differ.
STATE_FIXTURE="$HERE/fixtures/checks-state-test.yaml"

out=$(CHECKS_FILE="$STATE_FIXTURE" "$SCRIPT" fake-blocking-fail 2>&1); rc=$?
[ "$rc" -ne 0 ] \
  && ok "state: blocking read from checks.yaml fails the job (no forced state)" \
  || bad "a blocking check from the FILE passed while failing -- the promotion is inert: $out"

out=$(CHECKS_FILE="$STATE_FIXTURE" "$SCRIPT" fake-reporting-fail 2>&1); rc=$?
[ "$rc" -eq 0 ] \
  && ok "state: reporting read from checks.yaml does not fail the job (no forced state)" \
  || bad "a reporting check from the FILE failed the job (rc=$rc): $out"
grep -q "report-only" <<<"$out" \
  && ok "the reporting check says so in its own output" \
  || bad "reporting check did not identify itself as report-only: $out"

# The production fact Task 8 rests on, asserted rather than eyeballed. This
# READS the real checks.yaml; it never composes or runs a command from it --
# lookup-check.py only prints fields, so no check of ours can be triggered
# from here by a future edit to that file.
REAL_CHECKS="$HERE/../../checks.yaml"
[ -f "$REAL_CHECKS" ] || bad "the real checks.yaml is not at $REAL_CHECKS -- the two assertions below prove nothing"
for promoted in lockfile helm-lint; do
  st=$(python3 "$HERE/../lookup-check.py" "$REAL_CHECKS" "$promoted" 2>/dev/null | cut -d'|' -f1)
  [ "$st" = "blocking" ] \
    && ok "$promoted is blocking in the real checks.yaml" \
    || bad "$promoted is '$st' in the real checks.yaml, expected blocking"
done

echo; [ "$fails" -eq 0 ] && echo "PASS" || echo "FAILURES"
exit "$fails"
