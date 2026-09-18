import pathlib, subprocess, sys, unittest
HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
SCRIPT = HERE.parent / "drift-check.py"
FIXTURES = HERE / "fixtures"


def run(old, new, *extra):
    return subprocess.run([sys.executable, str(SCRIPT), old, new, *extra],
                          capture_output=True, text=True, cwd=REPO)


class TestDrift(unittest.TestCase):
    def test_positive_control_v0280_to_v0285(self):
        """THE control. Measured 2026-09-18: this pair changed 4 workflow files.
        Without it, a detector wired to a constant 0 passes the v0.29.0 case
        perfectly, because that pair genuinely changed nothing."""
        r = run("v0.28.0", "v0.28.5")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertEqual(r.stdout.count("\n" ) > 0, True)
        # exactly four files named
        named = [l for l in r.stdout.splitlines() if l.strip().startswith("-")]
        self.assertEqual(len(named), 4, r.stdout)

    def test_null_case_v0286_to_v0290(self):
        """Upstream's CI is byte-identical across this release."""
        r = run("v0.28.6", "v0.29.0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("no change", r.stdout.lower())

    def test_same_tag_is_no_change(self):
        r = run("v0.28.6", "v0.28.6")
        self.assertEqual(r.returncode, 0)

    def test_unknown_tag_fails_loudly(self):
        """Exact code and exact wording, not just 'anything other than 0/3' --
        a bare `assertNotEqual(rc, 0); assertNotEqual(rc, 3)` would pass just
        as well for an unrelated traceback (e.g. rc 1 from a bad import),
        which is not this refusal and must not be mistaken for it."""
        r = run("v0.28.6", "v0.0.0-nope")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("cannot read v0.0.0-nope", r.stdout + r.stderr)


class TestCrossReferenceIsHarmless(unittest.TestCase):
    """The checks.yaml cross-reference is a convenience: main() has already
    decided 0 vs 3 from the tag diff before it runs. Its own failure -- of
    any shape, not just the ones anticipated when it was written -- must
    report itself honestly and never flip that verdict or crash the process."""

    def test_missing_upstream_key_does_not_flip_the_verdict(self):
        bad = FIXTURES / "checks-missing-upstream.yaml"
        r = run("v0.28.0", "v0.28.5", "--checks", str(bad))
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        named = [l for l in r.stdout.splitlines() if l.strip().startswith("-")]
        self.assertEqual(len(named), 4, r.stdout)
        self.assertIn("could not cross-reference", r.stdout.lower())

    def test_two_checks_sharing_one_upstream_file_are_both_named(self):
        """The real checks.yaml has release-build AND sbom both mirroring
        build.yml, which the positive control changes. A 1:1 {upstream:
        name} dict silently keeps only the last one written for that key --
        this caught that live, with the committed checks.yaml, before it
        shipped."""
        r = run("v0.28.0", "v0.28.5")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("release-build (mirrors build.yml)", r.stdout)
        self.assertIn("sbom (mirrors build.yml)", r.stdout)


if __name__ == "__main__":
    unittest.main()
