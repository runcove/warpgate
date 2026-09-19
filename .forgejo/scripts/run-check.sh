#!/usr/bin/env bash
# Run one check from .forgejo/checks.yaml, in the right environment, with the
# right consequence for failure.
set -uo pipefail

# These hooks exist so this script's control flow (excepted/blocking/
# reporting, capped/uncapped, refusal-band handling) is testable without a
# real check command or a container runtime. Mirrors hardened-run.sh's own
# guard: same three CI markers, same exit code. If any of these leak into a
# real CI run -- via a copied env: block or a prior step's GITHUB_ENV -- they
# silently defeat the very logic they exist to test (the reviewer
# demonstrated FORGEJO_ACTIONS=true RUN_CHECK_FORCE_STATE=blocking
# RUN_CHECK_FORCE_RC=0 printing "PASS clippy" with no command ever run), so
# fail loudly instead of running as a quiet no-op.
for var in RUN_CHECK_DRY RUN_CHECK_FORCE_STATE RUN_CHECK_FORCE_RC; do
  val="${!var:-}"
  if [ -n "$val" ] && { [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${FORGEJO_ACTIONS:-}" ]; }; then
    echo "run-check: FATAL -- $var is set while CI/GITHUB_ACTIONS/FORGEJO_ACTIONS is present.
This variable exists only to test this script without a real check or container runtime; left
set inside real CI it would silently defeat the state/cap logic it is meant to test. Refusing to
run." >&2
    exit 92
  fi
done

HERE="$(cd "$(dirname "$0")" && pwd)"
CHECKS="${CHECKS_FILE:-$HERE/../checks.yaml}"

# Not `"${1:?...}"` -- that form kills the script via bash's own
# parameter-expansion error, exit 1, indistinguishable from an ordinary
# failure. A missing required argument is a refusal like the ones below it.
if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
  echo "run-check: FATAL -- usage: run-check.sh <check-name> (required argument missing). Refusing to run." >&2
  exit 93
fi
NAME="$1"

# The lookup is done by a helper so the shell never parses YAML, under a
# timeout so a hung lookup (a wedged interpreter, a filesystem stall on
# CHECKS) fails the job instead of hanging this script forever -- a timeout
# is a refusal, not a pass. RUN_CHECK_LOOKUP_TIMEOUT is a plain tunable, not
# a test hook: a caller raising or lowering it in real CI cannot make an
# unsafe check run uncapped, so it is deliberately not in the CI-leak guard
# above.
LOOKUP_TIMEOUT="${RUN_CHECK_LOOKUP_TIMEOUT:-10}"
LOOKUP=$(timeout "$LOOKUP_TIMEOUT" python3 "$HERE/lookup-check.py" "$CHECKS" "$NAME"); lookup_rc=$?
if [ "$lookup_rc" -eq 124 ]; then
  echo "run-check: FATAL -- lookup for '$NAME' timed out after ${LOOKUP_TIMEOUT}s. Refusing to run blind." >&2
  exit 94
elif [ "$lookup_rc" -ne 0 ]; then
  echo "run-check: no check named '$NAME' in $CHECKS" >&2
  exit 2
fi
STATE=$(cut -d'|' -f1 <<<"$LOOKUP")
COMPILES=$(cut -d'|' -f2 <<<"$LOOKUP")
TOOLS=$(cut -d'|' -f3 <<<"$LOOKUP")
COMMAND=$(cut -d'|' -f4- <<<"$LOOKUP")

# A lookup that "succeeded" but handed back nothing to run is not a pass --
# running an empty command would silently look identical to a check that ran
# and passed. Refuse instead of pretending.
[ -n "$COMMAND" ] || {
  echo "run-check: lookup for '$NAME' returned no command -- refusing to run nothing as if it passed" >&2
  exit 2
}

# Same reasoning, for the tools field: checks_lib.load() refuses an empty
# `tools:` list at YAML-load time, so this should be unreachable against a
# validated checks.yaml -- but lookup-check.py is a separate program from
# that validation, and a lookup that came back with no declared tools at all
# is exactly as untrustworthy as one that came back with no command.
[ -n "$TOOLS" ] || {
  echo "run-check: lookup for '$NAME' returned no required tools -- refusing to run without checking preconditions" >&2
  exit 2
}

STATE="${RUN_CHECK_FORCE_STATE:-$STATE}"

if [ "$STATE" = "excepted" ]; then
  REASON=$(timeout "$LOOKUP_TIMEOUT" python3 "$HERE/lookup-check.py" "$CHECKS" "$NAME" --reason) \
    || REASON="(reason unavailable)"
  echo "SKIP $NAME — excepted. $REASON"
  exit 0
fi

# The declared precondition: a check that names a tool it needs and doesn't
# have it never gets to run at all -- checked before either run path below
# (capped or uncapped), so a check that "PASS"es having never touched its
# own tool (measured 2026-09-18: `check-lockfile.sh` did exactly this with
# jq) is refused before it gets the chance. Deliberately AFTER the excepted
# check above, not before it: an excepted check never reaches a run path
# either, and demanding its tools be installed would block CI on a tool a
# permanently-opted-out check's own SKIP means nobody needs today.
#
# Also skipped when a test hook (RUN_CHECK_DRY / RUN_CHECK_FORCE_RC /
# RUN_CHECK_FORCE_STATE) is active. This is a deliberate bypass of a safety
# check, so it earns an explicit reason, not just a mention: those hooks
# exist precisely so this script's control flow is testable "without a real
# check command or a container runtime" (see the CI-leak guard above), and a
# real tool's presence on PATH is exactly the kind of real-environment fact
# they exist to let a test skip past. Concretely: this test suite itself is
# meant to run wherever this repo's CI does, and that runner is MEASURED
# (2026-09-18) to have no Rust toolchain at all -- without this bypass,
# every existing FORCE_RC/FORCE_STATE/DRY case against a compiling check
# (cargo-deny, clippy, schema-compat) would start failing at this
# precondition, for an environment reason unrelated to the control-flow
# logic those hooks exist to isolate and test. This cannot mask a real gap
# in production: the guard at the top of this script already refuses to run
# at all if any of these three is set alongside
# CI/GITHUB_ACTIONS/FORGEJO_ACTIONS, and the precondition itself still has
# its own direct test (tests/test-run-check.sh, "declared tool absent")
# that does not use any of these hooks.
#
# Every declared tool is checked, not just the first -- reporting only one
# missing tool per run is how a four-tool gap takes four CI runs to
# discover, and each of those runs costs a human a read.
#
# WHERE the question is asked is the whole of it (2026-09-19). Until today this
# gate ran `command -v` in the JOB container for every check, and then the
# capped ones went and ran their command INSIDE hardened-run.sh's container --
# a different image. So for every capped check the gate interrogated a
# filesystem the command would never touch: `cargo` was demanded where it is
# never used, while HARDENED_RUN_IMAGE, where it actually has to exist, was
# never asked. That is why the fork briefly grew a bespoke Rust job image
# (runs 518/523/525, withdrawn in d6c3a20a) -- an image built to satisfy a
# question being put to the wrong machine.
#
# So the gate splits on CAPPED, which is computed just above for this reason.

# Whether a check is capped is a safety decision, not a convenience one: an
# uncapped Rust build on this cluster has already taken the control plane
# down once (2026-09-15). So this defaults to CAPPED and only opts out on the
# one token that unambiguously means "does not compile" -- "true" and
# "unverified" both cap (checks_lib's rule for 'unverified', extended here to
# every other shape too), and so does anything unexpected: empty, garbled, a
# stale "True"/"False" from before compiles_token() existed, or a lookup that
# partially failed. An unrecognised value never gets to mean "safe to run
# uncapped" by accident.
#
# Moved above the tools gate on 2026-09-19: the gate cannot split on CAPPED
# while CAPPED is computed twenty lines below it. Nothing between the old and
# new position reads it, so this is a move, not a change.
CAPPED=yes
[ "$COMPILES" = "false" ] && CAPPED=no

IFS=',' read -r -a TOOL_LIST <<<"$TOOLS"

# UNCAPPED checks run their command right here, in the job container, so the
# job container is the right place to ask. Unchanged from the original gate.
if [ "$CAPPED" = "no" ] \
   && [ -z "${RUN_CHECK_DRY:-}" ] && [ -z "${RUN_CHECK_FORCE_RC:-}" ] && [ -z "${RUN_CHECK_FORCE_STATE:-}" ]; then
  missing_tools=()
  for t in "${TOOL_LIST[@]}"; do
    command -v "$t" >/dev/null 2>&1 || missing_tools+=("$t")
  done
  if [ "${#missing_tools[@]}" -gt 0 ]; then
    echo "REFUSE $NAME — required tool(s) not installed in the job container, where this uncapped check runs: ${missing_tools[*]} (exit 97). The environment cannot run this check; it never ran." >&2
    exit 97
  fi
fi

# CAPPED checks are asked the same question INSIDE the sandbox, by prefixing
# the probe to the command hardened-run.sh is handed. One container, not two:
# hardened-run.sh's last line is `docker exec ... "$@"`, so the inner exit
# status IS its exit status, and an inner 97 arrives at the 89-99 band handler
# below exactly as the job-container gate's 97 would have. A separate probe
# container would cost a second container start per capped check and prove the
# same thing.
#
# The message names WHICH filesystem was missing the tool. "required tool(s)
# not installed", with no location, is one sentence for two different
# environments -- and telling those apart is the entire point of this split.
TOOL_PROBE=""
if [ "$CAPPED" = "yes" ]; then
  probe_list=""
  for t in "${TOOL_LIST[@]}"; do
    # Quoted when composed. These names come from checks.yaml, which is ours
    # and validated, but building a shell string out of a data file unquoted
    # is a habit worth not having.
    probe_list+=" $(printf '%q' "$t")"
  done
  # Collects every missing tool before refusing, rather than exiting on the
  # first. The uncapped gate above has always done this; the capped probe
  # short-circuited, so a check missing four tools named one per run and a
  # four-tool gap cost four CI runs to discover -- each one a queue cycle and
  # a human read. Measured in run 539, the first run in which this probe ever
  # executed: `clippy` reported `just` and said nothing about `cargo`, which
  # it also needs. Both halves of the split now answer the same question with
  # the same completeness; the only difference left is WHERE they looked,
  # which is the difference that was the point.
  TOOL_PROBE="__miss=\"\"; for __t in${probe_list}; do command -v \"\$__t\" >/dev/null 2>&1 || __miss=\"\$__miss \$__t\"; done; if [ -n \"\$__miss\" ]; then echo \"REFUSE $(printf '%q' "$NAME") — required tool(s) not installed inside the sandbox, where this capped check runs:\$__miss (exit 97). The environment cannot run this check; it never ran.\" >&2; exit 97; fi; "
fi

# The eight variables sccache needs to help a capped/compiling check: the
# six cache-env.sh (Task 3) prints, plus the two AWS credentials it
# deliberately does not print itself. Named here, not valued -- passed to
# hardened-run.sh's --forward-env, which only crosses the cap boundary a
# name that is actually set and non-empty in THIS process's own
# environment. A cold run, or a run where cache-env.sh refused, forwards
# nothing and the check still runs, just uncached (hardened-run.sh reports
# the count and names so that silence is never how a cache miss looks).
#
# THIS LIST AND cache-env.sh's OUTPUT MUST AGREE. They are two hand-written
# lists in different files describing one set, so they can drift silently:
# a variable printed there but missing here is emitted, ignored, and never
# reaches the process that needs it. test-run-check.sh pins them to each
# other for exactly that reason -- SCCACHE_REGION was added on 2026-09-19
# and had to be added in both places.
CACHE_FORWARD_VARS=(RUSTC_WRAPPER SCCACHE_BUCKET SCCACHE_ENDPOINT
                     SCCACHE_REGION SCCACHE_S3_USE_SSL SCCACHE_S3_NO_CREDENTIALS
                     AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY)
FORWARD_FLAGS=()
for v in "${CACHE_FORWARD_VARS[@]}"; do FORWARD_FLAGS+=(--forward-env "$v"); done

# A DEAD CACHE MUST COST SPEED, NEVER CORRECTNESS. Run 573 is why this exists.
#
# `RUSTC_WRAPPER=sccache` is not scoped to caching: it sits in front of every
# rustc invocation, so an sccache that cannot start takes down work that never
# wanted a cache at all. Measured, same branch, one commit apart: with no cache
# (run 569) unit-tests PASSED 436 tests and sbom PASSED; with a cache that
# could not start (run 573) unit-tests FAILED, sbom FAILED on `cargo metadata`,
# and schema-compat went from a known FAIL 1 to REFUSE 96. A broken cache was
# strictly worse than no cache.
#
# THE PROBE HAS TO BE HERE, INSIDE THE SANDBOX. configure-cache.sh is the
# obvious home for it and is the wrong one: it runs in the JOB container, which
# has no sccache at all (sccache is installed by the ci-toolchain image, and
# only there). A probe there would prove a property of an environment that
# never runs the compiler -- the same mistake as run 567, where a prover and a
# consumer resolved the same names against different PATHs and disagreed
# forever, both correct.
#
# On failure it DEGRADES rather than refuses: `unset RUSTC_WRAPPER` and carry
# on. The check then runs exactly as it did before any of this was wired —
# capped, uncached, honest. A refusal would convert a cache outage into a red
# run, which is the same over-reaction in the other direction.
#
# The marker line is deliberately greppable and carries sccache's OWN words
# rather than a paraphrase. run-all-checks.sh collects it into the run summary,
# so a cache that has been dead for a week says so in every run instead of
# quietly becoming the new normal — the failure mode this arc keeps meeting,
# where the degraded state is indistinguishable from the good one.
#
# EVERY non-blank line is emitted, each separately prefixed, and no line is
# selected as "the" error. That is not tidiness, it is the fix for run 576.
# This block used to take the FIRST non-blank line, and sccache prints a status
# banner before it prints a cause, so all five markers in run 576 read
# `CACHE-UNAVAILABLE clippy — sccache: Starting the server...` and the actual
# reason was discarded with the rest of the captured text. A marker that cannot
# distinguish one cache failure from another is the exact defect this arc exists
# to catch, committed inside the guard built to catch it.
#
# Any rule for picking the interesting line is a guess about a format we do not
# control, and the cost of guessing wrong is a run that reports a cache outage
# without saying why — precisely what happened. Printing all of them cannot be
# wrong; at worst it is three lines instead of one, in a block that only appears
# when something is already broken.
#
# `--start-server` is the right call and `--show-stats` is not: cache-env.sh's
# own notes record that --show-stats never contacts the backend, so it reports
# a healthy all-zero blob against a dead bucket. Startup is the step that
# actually builds the S3 client, which is why run 573's failure surfaced there.
#
# NOT HANDLED, and said plainly rather than left to be discovered: if a server
# were already running, --start-server's exit status for that case is untested
# here, and a non-zero would make this degrade unnecessarily. It cannot arise
# today — hardened-run.sh starts a fresh container per check, so the probe
# always meets a cold sccache — and the consequence if that ever changes is a
# needlessly uncached build, i.e. slower, which is the direction this whole
# block is built to fail in.
# THE CAPPED CONTAINER CANNOT RESOLVE THE CACHE HOST, AND THE JOB CONTAINER CAN.
# Measured in run 604, three readings taken in the place the fault happens:
#
#   job container      nameserver 127.0.0.11 (upstream 10.96.0.10)   getent rc=0
#   plain dind container   nameserver 8.8.8.8 / 8.8.4.4             getent rc=2
#   same + cap flags       nameserver 8.8.8.8 / 8.8.4.4             getent rc=2
#
# The inner dind daemon inherits the job container's loopback resolver, treats
# a loopback nameserver as unusable, and falls back to Docker's built-in
# defaults -- Google's public servers, which cannot resolve a homelab name.
# That, and nothing else, is the `dns error: ... Name has no usable address`
# that has made every capped check run uncached since the cache was wired.
# The cap flags are provably irrelevant: readings 2 and 3 are byte-identical.
#
# So the lookup happens HERE, where it works, and the answer is carried across
# as a plain /etc/hosts entry. NOTHING IS TYPED: the host comes out of
# SCCACHE_ENDPOINT, the address out of getent. A hand-written address would be
# a second copy of a fact the DNS already holds -- the same pinned-value smell
# this repo refuses one level down, and it would go stale in silence.
#
# ON FAILURE THIS DEGRADES, IT DOES NOT REFUSE, and that is deliberate rather
# than lazy. The block below already settles the question for a dead cache --
# "a refusal would convert a cache outage into a red run, which is the same
# over-reaction in the other direction" -- and a name that will not resolve is
# a dead cache reached one step earlier. The marker is the same greppable one,
# so run-all-checks.sh collects it into the summary and a resolution failure
# is exactly as visible as any other cache outage.
# The general route, measured in run 608: give the capped container the
# cluster's own resolver and it resolves everything, not just the one name
# --add-host carries. Same run, same daemon, same image, one flag different:
# without it, 8.8.8.8/8.8.4.4 and rc=2 for the cache host; with
# `--dns 10.96.0.10`, `# Overrides: [nameservers]` and rc=0 for both a cluster
# name and a homelab name.
#
# NOTHING IS TYPED, and that is the point. Docker writes the address it
# forwards to into this job container's own /etc/resolv.conf as
# `# ExtServers: [...]`, every run. Deriving it there means there is no
# literal to go stale, and so nothing for a drift guard to police -- a guard
# for a pinned resolver was written and deleted precisely because the value
# turned out to be readable.
#
# REFUSED RATHER THAN GUESSED. The derivation demands exactly one address and
# demands it be an IPv4 literal inside 10.96.0.0/12, the cluster service
# range. A runner reconfigured to forward straight to a public resolver would
# otherwise be derived into the sandbox as "the cluster resolver", quietly
# sending every lookup in every capped check off-site. On anything unexpected
# this says so and falls back to --add-host, which needs only this container's
# own resolution and so fails independently. Both routes are kept for that
# reason: --dns needs kube-dns reachable, --add-host does not.
#
# THE MARKER IS DELIBERATELY NOT `CACHE-UNAVAILABLE`. Failing to derive a
# resolver is not a cache outage -- the --add-host route still carries the
# cache host, so the cache works. Reusing the outage marker here would put a
# healthy cache in the run summary's outage list, which is the good state
# reported as the degraded one: the same indistinguishability this arc keeps
# meeting, pointing the other way. An existing test caught exactly that.
CACHE_DNS=()
if [ "$CAPPED" = "yes" ]; then
  # Overridable ONLY so the tests can hand it a fixture. Run 580's defect was
  # a suite whose verdict came from the host's own files; a derivation that
  # reads /etc/resolv.conf unconditionally would reproduce it one script over,
  # passing on a machine with no ExtServers line for the wrong reason.
  __rf="${RUN_CHECK_RESOLV_CONF:-/etc/resolv.conf}"
  __rl=$(grep -m1 '^# ExtServers:' "$__rf" 2>/dev/null || true)
  if [ -z "$__rl" ]; then
    echo "CACHE-DNS-FALLBACK $NAME — no '# ExtServers:' line in $__rf, so the cluster resolver could not be derived; falling back to the single --add-host mapping" >&2
  else
    __rs=${__rl#*[}; __rs=${__rs%]*}
    __rn=$(printf '%s\n' "$__rs" | tr ',' '\n' | grep -c '[^[:space:]]' || true)
    __r1=$(printf '%s\n' "$__rs" | tr ',' '\n' | head -1 | tr -d '[:space:]')
    if [ "$__rn" -ne 1 ]; then
      echo "CACHE-DNS-FALLBACK $NAME — '# ExtServers:' lists $__rn servers ('$__rs'); refusing to pick one, falling back to --add-host" >&2
    else
      case "$__r1" in
        *[!0-9.]*) __r1="" ;;
        *.*.*.*.*) __r1="" ;;
        *.*.*.*)   : ;;
        *)         __r1="" ;;
      esac
      case "$__r1" in
        10.9[6-9].*|10.10[0-9].*|10.11[0-1].*) CACHE_DNS=(--dns "$__r1") ;;
        *) echo "CACHE-DNS-FALLBACK $NAME — '# ExtServers:' names '$__r1', which is not an IPv4 address in the cluster service range 10.96.0.0/12; refusing to hand it to the sandbox as a resolver, falling back to --add-host" >&2 ;;
      esac
    fi
  fi
fi

CACHE_ADD_HOST=()
if [ "$CAPPED" = "yes" ] && [ -n "${SCCACHE_ENDPOINT:-}" ]; then
  __ch="${SCCACHE_ENDPOINT#*://}"; __ch="${__ch%%:*}"; __ch="${__ch%%/*}"
  if [ -z "$__ch" ]; then
    echo "CACHE-UNAVAILABLE $NAME — SCCACHE_ENDPOINT is set to '${SCCACHE_ENDPOINT}', which yields no hostname" >&2
  else
    # ahostsv4, not `hosts`: --add-host takes one address and docker wants an
    # IPv4 here; `getent hosts` would happily hand back an IPv6 first.
    __cip=$(getent ahostsv4 "$__ch" 2>/dev/null | awk 'NR==1{print $1}')
    if [ -n "$__cip" ]; then
      CACHE_ADD_HOST=(--add-host "$__ch:$__cip")
    else
      echo "CACHE-UNAVAILABLE $NAME — could not resolve '$__ch' in the job container, so the capped container was given no route to the cache. The check runs uncached." >&2
    fi
  fi
fi

CACHE_PROBE=""
if [ "$CAPPED" = "yes" ]; then
  CACHE_PROBE="if [ -n \"\${RUSTC_WRAPPER:-}\" ]; then if __ce=\$(sccache --start-server 2>&1); then :; else __cf=\$(printf '%s\n' \"\$__ce\" | grep '[^[:space:]]' || true); if [ -n \"\$__cf\" ]; then printf '%s\n' \"\$__cf\" | while IFS= read -r __cl; do echo \"CACHE-UNAVAILABLE $(printf '%q' "$NAME") — \$__cl\" >&2; done; else echo \"CACHE-UNAVAILABLE $(printf '%q' "$NAME") — sccache could not start and printed nothing\" >&2; fi; unset RUSTC_WRAPPER; fi; fi; "
fi

if [ "${RUN_CHECK_DRY:-}" = "1" ]; then
  if [ "$CAPPED" = "yes" ]; then
    # The probe is printed as part of the command because it IS part of the
    # command -- this is the only place the capped tools gate can be observed
    # without a container engine, and baba has none (podman is off-limits,
    # Ruling 45). tests/test-run-check.sh asserts on it here.
    echo "would run via hardened-run: ${TOOL_PROBE}${CACHE_PROBE}$COMMAND"
  else
    echo "would run directly: $COMMAND"
  fi
  exit 0
fi

if [ -n "${RUN_CHECK_FORCE_RC:-}" ]; then
  rc="$RUN_CHECK_FORCE_RC"
elif [ "$CAPPED" = "yes" ]; then
  # --source/--workdir: hardened-run.sh's capped container starts empty --
  # no -v, no docker cp, nothing puts the repo inside it on its own. Every
  # capped check needs the source tree where it runs, so this is not
  # optional here even though hardened-run.sh itself keeps the flags
  # optional for other callers. --verify-file names Cargo.toml because THIS
  # repo is a cargo workspace -- hardened-run.sh itself names no project, so
  # that fact belongs here, not there.
  #
  # `bash -c`, NOT `bash -lc`. This was `-lc` until run 567, and the `-l` is
  # what that run actually died of. A login shell sources /etc/profile, and
  # Debian's /etc/profile (base-files 12.4+deb12u15, read from the package the
  # image installs) does not EXTEND PATH, it ASSIGNS it:
  #
  #   if [ "$(id -u)" -eq 0 ]; then
  #     PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  #
  # so the toolchain image's own `ENV PATH=/usr/local/cargo/bin:$PATH` is
  # discarded before the probe below runs a single `command -v`. Run 567
  # measured exactly that split: git, tar, python3, npm (/usr/bin) and oasdiff
  # (/usr/local/bin) were found, while just, cargo, cargo-cranky,
  # cargo-llvm-cov and cargo-cyclonedx -- every resident of
  # /usr/local/cargo/bin, and only those -- refused 97 as "not installed",
  # inside the very image whose own assertion had just proved all nine present.
  #
  # Both readings were true. assert-toolchain.sh proves reachability via
  # `docker run IMAGE assert-toolchain.sh`, which is not a login shell; the
  # check asked through one. A prover and a consumer that resolve the same
  # name against different PATHs will disagree for as long as nobody makes
  # them use the same shell. `docker exec` already hands us the image's
  # environment (hardened-run.sh forwards PATH for nobody -- run 567 logged
  # "forwarded 0 variable(s)"), so -c inherits exactly what the image declared
  # and -l was never buying anything: nothing in these images ships a
  # /etc/profile.d entry that a check needs.
  "$HERE/hardened-run.sh" --cpus "${CI_CPUS:-4}" --memory "${CI_MEMORY:-7g}" \
    --label "check-$NAME" --source "$PWD" --workdir /src --verify-file Cargo.toml \
    ${CACHE_DNS[@]+"${CACHE_DNS[@]}"} \
    ${CACHE_ADD_HOST[@]+"${CACHE_ADD_HOST[@]}"} \
    "${FORWARD_FLAGS[@]}" -- bash -c "${TOOL_PROBE}${CACHE_PROBE}$COMMAND"
  rc=$?
else
  # Same change, same reason. This path runs in the JOB container, where the
  # uncapped checks' tools (jq, helm, biome, find, sed) all live in /usr/local/bin
  # or /usr/bin and so survive /etc/profile's assignment -- which is precisely
  # why the trap sat here unsprung and only fired once an image put tools
  # somewhere else. Fixed in both places rather than only where it bit.
  bash -c "$COMMAND"
  rc=$?
fi

# The backstop: 127 is the shell's own "command not found", and Step 1 above
# only catches a tool someone remembered to declare. This catches the rest
# -- a tools: list that has drifted from what the command actually invokes,
# or a tool missing deeper inside the check (e.g. one `just` recipe shells
# out to) -- by converting it to the same 97 Step 1 would have used had the
# gap been declared. Applied uniformly, including the RUN_CHECK_FORCE_RC
# test-hook path above, so this conversion is exercised without needing a
# real command that exits 127.
if [ "$rc" -eq 127 ]; then
  echo "run-check: $NAME hit \"command not found\" (exit 127) -- converting to 97: the environment is missing a tool this check needs, so nothing was proven." >&2
  rc=97
fi

# Exit codes 89-99 are hardened-run.sh's reserved "could not run safely"
# band (documented in its own header: 90 cap read-back failed or didn't
# match, 91 container could not be created, 92 a test hook leaked into CI,
# 93 required configuration missing -- and deliberately treated as the
# WHOLE band here, not just those four, because enumerating only the codes
# we know about is how a new one gets misread as an ordinary check result).
# A refusal is not a statement about the check -- it means the check never
# safely ran at all -- so it is NEVER downgraded by `state: reporting` and
# never reached for an `excepted` check (that path already returned above).
# This applies on the uncapped path too: a real check command that happens
# to exit in this band is a coincidence, and misreporting it as a refusal is
# the safe direction of error -- loud and investigable, never silent.
if [ "$rc" -ge 89 ] && [ "$rc" -le 99 ]; then
  echo "REFUSE $NAME — did not run safely (exit $rc, reserved band 89-99). This is not a pass or a fail; investigate before retrying." >&2
  exit "$rc"
fi

if [ "$rc" -eq 0 ]; then
  echo "PASS $NAME"
  exit 0
fi

if [ "$STATE" = "blocking" ]; then
  echo "FAIL $NAME (blocking) — exit $rc" >&2
  exit "$rc"
fi

echo "FAIL $NAME (report-only, does not fail the job) — exit $rc"
exit 0
