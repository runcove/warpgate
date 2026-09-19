"""Every workflow job must declare a timeout-minutes.

Why this file exists: ci.yml ran unbounded from the day it was written until
2026-09-19, and nobody noticed because for most of that time nothing in it
could hang -- the five capped checks refused 97 within seconds. The moment
they started compiling (run 569), an unbounded job became a run that can never
reach a terminal state while holding a slot on a shared forge, where "still
running" and "wedged" are indistinguishable to anyone reading the run list.

Three of our four workflows already carried a bound. The gap was an oversight,
not a decision, and an oversight of exactly the kind a test catches for free:
this one fails for a bound REMOVED and, more usefully, for a NEW workflow or a
new job added without one, which is the case a human reviewer is least likely
to catch.

Deliberately NOT asserted: the size of the bound. That is a judgement made from
measured durations and it differs per workflow (build-image 170,
build-ci-toolchain 120, ci 120, upstream-watch 20). A test pinning the numbers
would have to be edited every time a bound is legitimately retuned, and a test
edited that often stops being read. The sanity range below only rejects values
that cannot be anyone's intent.
"""

import pathlib
import unittest

import yaml

HERE = pathlib.Path(__file__).resolve().parent
WORKFLOWS = HERE.parents[1] / "workflows"


def workflow_files():
    return sorted(
        p for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml")
    )


def jobs_missing_a_timeout(docs):
    """The whole rule, in one place.

    `docs` is an iterable of (label, parsed-workflow). Returned as a list of
    "<label>:<job>" so the failure message NAMES the offenders -- a bare count,
    or a bare True/False, would leave the reader to find them by hand.

    Factored out so the positive control below can drive THIS function with a
    mutated document. A control that re-implements the rule inline only proves
    the copy works.
    """
    missing = []
    for label, doc in docs:
        for job_name, job in ((doc or {}).get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            # A `uses:` job is a reusable-workflow call; the bound lives in the
            # called workflow, which this same sweep checks when it is ours.
            if "uses" in job:
                continue
            if "timeout-minutes" not in job:
                missing.append(f"{label}:{job_name}")
    return missing


def parsed_workflows():
    return [(p.name, yaml.safe_load(p.read_text())) for p in workflow_files()]


class TestWorkflowTimeouts(unittest.TestCase):
    def test_there_are_workflows_to_check(self):
        """A zero-file sweep passes every assertion below and proves nothing.

        Without this, a renamed directory or a bad glob turns this whole file
        into a test that always passes -- the failure mode the arc keeps
        meeting in other costumes.
        """
        files = workflow_files()
        self.assertGreaterEqual(
            len(files),
            4,
            f"expected at least the four known workflows under {WORKFLOWS}, "
            f"found {[p.name for p in files]}",
        )

    def test_every_job_declares_a_timeout(self):
        missing = jobs_missing_a_timeout(parsed_workflows())
        self.assertEqual(
            missing,
            [],
            "every workflow job must declare timeout-minutes; an unbounded job "
            "that hangs never reaches a terminal state and holds a runner slot "
            "on a shared forge. Missing: " + ", ".join(missing),
        )

    def test_the_sweep_examined_every_job(self):
        """The sweep must have looked at a plausible number of jobs.

        `jobs_missing_a_timeout` returns [] both when every job is bounded and
        when it walked no jobs at all. This counts what it walked, so the
        clean result above means "all of them pass" rather than "there was
        nothing to fail".
        """
        walked = [
            f"{label}:{name}"
            for label, doc in parsed_workflows()
            for name in ((doc or {}).get("jobs") or {})
        ]
        self.assertGreaterEqual(
            len(walked), 4, f"only walked {walked}; expected one job per workflow"
        )

    def test_declared_timeouts_are_sane(self):
        """Rejects only values that cannot be anyone's intent, not a policy."""
        bad = []
        for path in workflow_files():
            doc = yaml.safe_load(path.read_text())
            for job_name, job in (doc.get("jobs") or {}).items():
                if not isinstance(job, dict) or "timeout-minutes" not in job:
                    continue
                v = job["timeout-minutes"]
                if not isinstance(v, int) or isinstance(v, bool):
                    bad.append(f"{path.name}:{job_name} = {v!r} (not an int)")
                elif not 1 <= v <= 360:
                    bad.append(f"{path.name}:{job_name} = {v} (outside 1..360)")
        self.assertEqual(bad, [], "; ".join(bad))

    def test_the_check_would_actually_fail(self):
        """Positive control, driving the real function with a real mutation.

        Takes the live ci.yml, removes the bound from its job, and requires
        `jobs_missing_a_timeout` -- the same function the assertion above
        uses -- to name it. If this ever passes trivially, the sweep above is
        not proving what its name claims.
        """
        doc = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())
        self.assertIn(
            "timeout-minutes",
            doc["jobs"]["checks"],
            "fixture drift: ci.yml's checks job is expected to HAVE a bound "
            "here, so that removing it below is a real mutation rather than a "
            "no-op against an already-unbounded job",
        )
        del doc["jobs"]["checks"]["timeout-minutes"]
        self.assertEqual(
            jobs_missing_a_timeout([("ci.yml", doc)]), ["ci.yml:checks"]
        )

    def test_a_uses_job_is_not_reported(self):
        """The one exemption, pinned so it cannot quietly widen.

        A reusable-workflow call has no place to put a bound. Anything else
        without one must still be reported, so this also checks the negative.
        """
        doc = {"jobs": {"call": {"uses": "./.forgejo/workflows/other.yml"},
                        "real": {"runs-on": "docker"}}}
        self.assertEqual(jobs_missing_a_timeout([("x.yml", doc)]), ["x.yml:real"])


if __name__ == "__main__":
    unittest.main()
