# Exit codes 89-99: the "could not run safely" band

Shared across every script under `.forgejo/scripts/`. A code in this band is
never a statement about whatever command was asked to run — it means the
thing never ran (or never finished) safely at all, so it must never be
treated as an ordinary pass/fail result. `run-check.sh` treats the *whole*
band this way for exactly that reason: enumerating only the codes it
recognises is how a new one would get misread as an ordinary check result.

This file is the single registry. A script's own header may still note its
own codes for a reader working in just that file, but the authoritative,
complete list — the one to check before allocating a new code, so it doesn't
collide with one owned by a script you didn't happen to open — lives here.
Add a row here in the same commit that adds a new code.

**This is enforced, not just asked for.**
`tests/test-exit-codes-registry.sh` greps every `exit 9[0-9]` site in
`.forgejo/scripts/*.sh` and `*.py` (excluding `tests/` itself — those sites
are assertions about expected codes, not allocations) and fails, naming the
exact script and code, if that pairing isn't listed below. A stale registry
is a red test, not a hopeful comment: this file went stale within hours of
being created (missed `preflight.sh`'s 93, added the same day by a
different session) precisely because it was a grep of a moving tree
presented as a fact rather than a checked one.

| Code | Script | Meaning |
|------|--------|---------|
| 90 | `hardened-run.sh` | The CPU/memory cap was read back after the container started and either the read-back failed or didn't match what was requested — the one bound this script exists to guarantee did not hold. |
| 91 | `hardened-run.sh` | The capped container could not be created/started at all. |
| 92 | `hardened-run.sh`, `run-check.sh` | A test hook (`HARDENED_RUN_*` / `RUN_CHECK_*`) was set while `CI`/`GITHUB_ACTIONS`/`FORGEJO_ACTIONS` is present — those hooks exist only to test the script without a container runtime, and left set in real CI they would silently defeat the logic they're meant to test. |
| 93 | `cache-env.sh`, `configure-cache.sh`, `hardened-run.sh`, `preflight.sh`, `run-check.sh`, `version.sh` | A required argument or piece of configuration is missing or unrecognised (a bucket name, `S3_ENDPOINT`, `HARDENED_RUN_IMAGE`, python3/PyYAML/docker/dockerd for `preflight.sh`, a check name, a `version.sh` subcommand/operand). Never bash's own `${1:?}`/`${2:?}` — that form exits 1, indistinguishable from an ordinary failure and outside this band entirely. |
| 94 | `run-check.sh` | The check lookup (`lookup-check.py`) timed out — a hung lookup fails the job instead of hanging forever; a timeout is a refusal, not a pass. |
| 95 | `version.sh` | `--next` found no upstream `vX.Y.Z` tag reachable from `HEAD` — there is no base to build a version on. |
| 96 | `version.sh` | `--next` could not establish that its view of existing `<base>-cove.*` tags is complete before trusting an empty result to mean "no cove release yet for this base". Covers a shallow clone (`git rev-parse --is-shallow-repository` != `false`) and a full clone whose fetch simply never brought tags (no `--tags`, a checkout step that skipped them) — the latter is caught by comparing against `git ls-remote`, since local history alone can't tell "no releases yet" from "my tags never arrived" apart. Also covers the remote query itself failing or timing out: a refusal costs a rerun, a wrong guess here republishes an existing release. |
| 97 | `run-check.sh`, `check-lockfile.sh` | A tool this check requires is not installed. `run-check.sh` checks every check's declared `tools:` list against `PATH` before either run path (capped or uncapped); a check that never gets that far never gets the chance to print a false PASS with its own tool missing (measured 2026-09-18: `check-lockfile.sh` did exactly that with `jq`). Also the backstop for a raw 127 ("command not found") hit during or after a check's own command, converted to 97 by `run-check.sh` — this catches a `tools:` list that has drifted from what the command actually invokes, and a tool missing deeper inside a check. `check-lockfile.sh` additionally verifies its own `jq`/`find` up front and refuses with 97 itself, so it refuses the same way run standalone or through `run-check.sh`. |
| 98 | *(reserved)* | Not yet allocated — reserved for Task 7B (source delivery into the capped container). Do not use until that task claims it. |
| 99 | `check-lockfile.sh`, `run-all-checks.sh` | The check (or the check-runner itself) found nothing to examine, and that is neither a pass nor a fail — only "nothing was proven". Distinct from 97: the tool(s) ran fine, there was simply nothing to point them at. `check-lockfile.sh` exits 99 when `find` matches zero `package-lock.json` files — the concrete case is a check running before source has been delivered into the capped container (the gap Task 7B closes; until then, or if that delivery ever breaks again, this is what an empty checkout looks like, and it must not read as either a clean pass or a code problem). `run-all-checks.sh` exits 99 the same way, one level up, if it enumerates zero checks from `checks.yaml` — either because `list-checks.py` itself failed (its exit status is checked directly, not left to a process substitution to swallow) or, as defence in depth, because it printed nothing at all despite exiting 0. |

Codes outside 89-99 (e.g. `run-check.sh`'s plain `2` for "no such check", or a
wrapped command's own exit code) are ordinary results, not refusals, and are
not tracked here.
