import datetime, pathlib, subprocess, sys, tempfile, unittest
HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import checks_lib

REPO = HERE.parents[2]

def write(body):
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
    f.write(body); f.close()
    return f.name

GOOD = """
upstream_tag: v0.28.6
checks:
  - name: cargo-deny
    upstream: cargo-deny.yml
    command: cargo deny check
    compiles: false
    state: reporting
    tools: [cargo, cargo-deny]
"""

class TestLoad(unittest.TestCase):
    def test_loads_a_good_file(self):
        checks = checks_lib.load(write(GOOD))
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["name"], "cargo-deny")
        self.assertIs(checks[0]["compiles"], False)

    def test_unknown_state_is_refused(self):
        bad = GOOD.replace("state: reporting", "state: enabled")
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("cargo-deny", str(e.exception))
        self.assertIn("enabled", str(e.exception))

    def test_exception_without_reason_is_refused(self):
        bad = GOOD.replace("state: reporting",
                           "state: excepted\n    review_by: 2026-12-01")
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("reason", str(e.exception))

    def test_exception_without_review_by_is_refused(self):
        bad = GOOD.replace("state: reporting",
                           "state: excepted\n    reason: upstream test assumes ghcr")
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("review_by", str(e.exception))

    def test_a_complete_exception_is_accepted(self):
        ok = GOOD.replace(
            "state: reporting",
            "state: excepted\n    reason: upstream test assumes ghcr"
            "\n    review_by: 2026-12-01")
        checks = checks_lib.load(write(ok))
        self.assertEqual(checks[0]["review_by"], datetime.date(2026, 12, 1))

    def test_duplicate_names_are_refused(self):
        bad = GOOD + GOOD.split("checks:")[1]
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("duplicate", str(e.exception).lower())

    def test_missing_tools_field_is_refused(self):
        """Task 7A: tools is now REQUIRED, same shape as the other required
        fields -- missing entirely raises ValueError, not a KeyError further
        downstream where the message would no longer name the check."""
        bad = GOOD.replace("\n    tools: [cargo, cargo-deny]", "")
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("cargo-deny", str(e.exception))
        self.assertIn("tools", str(e.exception))

    def test_empty_tools_list_is_refused(self):
        """A check that declares it needs nothing is almost always a check
        whose author did not look -- the key being present is not enough."""
        bad = GOOD.replace("tools: [cargo, cargo-deny]", "tools: []")
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("cargo-deny", str(e.exception))
        self.assertIn("tools", str(e.exception))

    def test_scalar_tools_is_refused(self):
        """tools must be a LIST, not a scalar -- a check can need more than
        one binary. A bare string would still validate as non-empty/truthy
        in Python, so this has to be checked explicitly, not inferred from
        the empty-list check above."""
        bad = GOOD.replace("tools: [cargo, cargo-deny]", "tools: cargo")
        with self.assertRaises(ValueError) as e:
            checks_lib.load(write(bad))
        self.assertIn("cargo-deny", str(e.exception))
        self.assertIn("tools", str(e.exception))

class TestCompilesToken(unittest.TestCase):
    """A later task's shell compares this string to decide whether a check
    runs under a memory/CPU cap. str(bool(...)) would give "True"/"False",
    which a shell `= "true"` comparison never matches — the wrong-direction
    failure (a compiling check running uncapped)."""

    def test_true_is_lowercase_string(self):
        self.assertEqual(checks_lib.compiles_token({"compiles": True}), "true")

    def test_false_is_lowercase_string(self):
        self.assertEqual(checks_lib.compiles_token({"compiles": False}), "false")

    def test_unverified_passes_through(self):
        self.assertEqual(
            checks_lib.compiles_token({"compiles": "unverified"}), "unverified")

class TestValidatorAgainstUpstream(unittest.TestCase):
    """The validator must check the `upstream:` file really exists at the tag.
    Without this, a renamed upstream workflow leaves a check pointing at nothing
    and nobody finds out."""

    def run_validator(self, path):
        return subprocess.run(
            [sys.executable, str(HERE.parent / "validate-checks.py"), path],
            capture_output=True, text=True, cwd=REPO)

    def test_real_file_passes(self):
        r = self.run_validator(write(GOOD))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_upstream_file_fails(self):
        bad = GOOD.replace("cargo-deny.yml", "does-not-exist.yml")
        r = self.run_validator(write(bad))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does-not-exist.yml", r.stdout + r.stderr)

    # --- the command must exist, not only be well-formed ------------------
    # `reprotest` named .forgejo/scripts/reprotest.sh for as long as the check
    # list existed, and no such file was ever committed. This validator said
    # "ok: 11 check(s) valid" the whole time. The check is `state: excepted`,
    # so nothing ran it and nothing complained; un-excepting it would have
    # failed with "No such file or directory" in the ORDINARY range, which no
    # exit code distinguishes from a verdict on our code.

    def test_a_command_naming_a_missing_repo_script_fails(self):
        bad = GOOD.replace("command: cargo deny check",
                           "command: .forgejo/scripts/definitely-not-here.sh")
        r = self.run_validator(write(bad))
        self.assertNotEqual(r.returncode, 0,
                            "a command naming a file we do not have was accepted")
        self.assertIn("definitely-not-here.sh", r.stdout + r.stderr,
                      "the refusal does not name the missing path")

    def test_a_command_naming_a_non_executable_repo_file_fails(self):
        # Distinct from missing: present but not runnable fails the same way at
        # run time and must not be waved through because the path resolves.
        bad = GOOD.replace("command: cargo deny check",
                           "command: .forgejo/checks.yaml")
        r = self.run_validator(write(bad))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not executable", r.stdout + r.stderr)

    def test_a_real_repo_script_passes(self):
        # The control. Without it, the two assertions above would also be
        # satisfied by a validator that refused every command with a slash in
        # it, which would refuse the whole real check list.
        ok = GOOD.replace("command: cargo deny check",
                          "command: .forgejo/scripts/check-lockfile.sh")
        r = self.run_validator(write(ok))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_plain_program_name_is_not_treated_as_a_path(self):
        # `cargo`, `helm`, `mkdir` are resolved wherever the check runs, which
        # is a sandbox image, not here. Refusing them would be a confident
        # false refusal about tools that are present there and absent here.
        for cmd in ("cargo deny check",
                    "cd warpgate-web && biome ci .",
                    "mkdir -p warpgate-web/dist && just clippy"):
            with self.subTest(cmd=cmd):
                r = self.run_validator(write(GOOD.replace("command: cargo deny check",
                                                          f"command: {cmd}")))
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_committed_checks_file_is_valid(self):
        r = self.run_validator(str(REPO / ".forgejo" / "checks.yaml"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

if __name__ == "__main__":
    unittest.main()
