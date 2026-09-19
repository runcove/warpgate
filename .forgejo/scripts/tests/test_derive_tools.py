"""derive-tools.py: does it report what a script actually invokes?

WHY THIS SUITE IS FIXTURE-FIRST. Three hand-rolled sweeps preceded the deriver.
Each printed a confident answer and two were wrong, in opposite directions:

  - a heredoc-stripping regex under DOTALL spanned from one heredoc to a later
    one and deleted everything between, losing a real `| sed ...`. The result
    LOOKED clean, because a sweep that sees less reports less.
  - a grep without comment stripping reported `jq` and `just` for schema-compat,
    where both occur only in prose explaining the script was rewritten to stop
    using them.

Both were found by opening the file and reading the cited lines, not by the
sweep. So fixtures/tool-invocations.sh states the expected answer in its own
header, written before the deriver existed, and carries one case per failure
mode. A deriver checked only against the scripts it was written from would
agree with itself and prove nothing — the defect this whole arc keeps finding.
"""
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPTS = HERE.parent
FIXTURE = HERE / "fixtures" / "tool-invocations.sh"

_spec = importlib.util.spec_from_file_location(
    "derive_tools", str(SCRIPTS / "derive-tools.py"))
dt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dt)


def names(text):
    return set(dt.invocations(text))


class TestFixture(unittest.TestCase):
    """The fixture's header names the expected set; this asserts it exactly."""

    EXPECTED = {"banana", "cat", "cherry", "damson", "elderberry", "fig", "grape"}

    def test_exact_set(self):
        # Exact equality, never a subset check: a subset assertion passes on a
        # deriver that reports everything, and a superset one passes on a
        # deriver that reports nothing.
        self.assertEqual(names(FIXTURE.read_text()), self.EXPECTED)

    def test_the_fixture_header_still_matches_this_expectation(self):
        # The fixture states its own answer in prose. If someone edits one and
        # not the other, the two stop describing the same thing and this suite
        # silently starts testing the wrong list.
        head = FIXTURE.read_text().split("\n")
        line = next(l for l in head if "EXPECTED, exactly:" in l)
        stated = set(line.split("EXPECTED, exactly:")[1].split())
        self.assertEqual(stated, self.EXPECTED)


class TestEachFailureMode(unittest.TestCase):
    """One test per way a sweep can be wrong, stated as its own case."""

    def test_a_comment_is_not_an_invocation(self):
        self.assertEqual(names("# apricot --version\n"), set())

    def test_a_double_quoted_string_is_data(self):
        self.assertEqual(names('echo "blackcurrant --force"\n'), set())

    def test_a_single_quoted_string_is_data(self):
        self.assertEqual(names("echo 'blueberry --force'\n"), set())

    def test_a_multi_line_string_is_data_on_every_line(self):
        # The case that made an early run report `refuse`, `would` and
        # `Tracked`: quote state must carry ACROSS lines, because a shell
        # string does.
        text = 'echo "first line\nsecond mango line\nthird line" >&2\n'
        self.assertEqual(names(text), set())

    def test_a_heredoc_body_is_data_but_the_opening_command_is_not(self):
        text = "cat <<'EOF'\ncloudberry --inside\nEOF\n"
        self.assertEqual(names(text), {"cat"})

    def test_a_heredoc_does_not_swallow_the_rest_of_the_file(self):
        # The false negative that lost check-lockfile.sh's sed.
        text = "cat <<'EOF'\nbody\nEOF\nreal_program --after\n"
        self.assertIn("real_program", names(text))

    def test_a_comment_mentioning_a_heredoc_opens_nothing(self):
        # Found by the fixture: a COMMENT containing `<<'EOF'` while explaining
        # heredocs opened one that never closed, blanking everything after it.
        text = "# see `cat <<'EOF'` for why\nkiwi --still-found\n"
        self.assertEqual(names(text), {"kiwi"})

    def test_a_pipeline_stage_is_a_command_position(self):
        # The shape of the real finding: check-lockfile.sh:101.
        self.assertEqual(names("echo \"$m\" | sed 's/^/  /'\n"), {"sed"})

    def test_separators_open_command_positions(self):
        self.assertEqual(
            names("damson --q && elderberry; grape\nx=$(fig --print)\n"),
            {"damson", "elderberry", "grape", "fig"})

    def test_assignment_prefixes_are_skipped_but_the_command_is_found(self):
        self.assertEqual(names("SOURCE_DATE_EPOCH=0 cargo build\n"), {"cargo"})

    def test_an_assignment_right_hand_side_is_not_a_call(self):
        self.assertEqual(names("DATE_CMD=date\n"), set())

    def test_builtins_and_keywords_are_not_programs(self):
        self.assertEqual(names("if [ -n \"$x\" ]; then return 0; fi\n"), set())

    def test_command_v_is_a_builtin(self):
        # check-lockfile.sh:37 uses `command -v`; reporting it would have sent
        # someone looking for a program called `command`.
        self.assertEqual(names("command -v jq >/dev/null\n"), set())

    def test_a_locally_defined_function_is_not_an_external_tool(self):
        # schema-compat's own say/refuse/generate helpers. Declaring these
        # would make the run-time gate demand binaries that never existed.
        text = "say() { echo \"$*\"; }\nsay hello\n"
        self.assertEqual(names(text), set())

    def test_a_path_is_left_to_the_caller(self):
        self.assertEqual(names("./scripts/thing.sh --run\n"), set())


class TestAgainstTheRealScripts(unittest.TestCase):
    """The two real cases that motivated the file, asserted by name and line."""

    def test_finds_check_lockfile_sed(self):
        got = dt.invocations((SCRIPTS / "check-lockfile.sh").read_text())
        self.assertIn("sed", got,
                      "the undeclared sed (runcove-tbxh) must still be found")

    def test_does_not_report_schema_compat_comment_only_tools(self):
        got = names((SCRIPTS / "check-schema-compat.sh").read_text())
        for ghost in ("jq", "just"):
            self.assertNotIn(
                ghost, got,
                f"{ghost} appears only in prose saying the script stopped using it")


class TestUndeclaredForCheck(unittest.TestCase):
    """The per-check comparison the validator calls."""

    REPO = str(HERE.parents[2])

    def _lockfile_check(self, tools):
        return {"name": "lockfile",
                "command": ".forgejo/scripts/check-lockfile.sh",
                "tools": tools}

    def test_declaring_everything_is_clean(self):
        self.assertEqual(
            dt.undeclared_for_check(self._lockfile_check(["jq", "find", "sed"]), self.REPO),
            [])

    def test_a_missing_declaration_is_reported_with_file_and_line(self):
        # The positive control. Without it, "every check is clean" could mean
        # the comparison looks at nothing — which is the failure this arc names
        # most often.
        got = dt.undeclared_for_check(self._lockfile_check(["jq", "find"]), self.REPO)
        self.assertEqual([n for n, _ in got], ["sed"])
        self.assertIn("check-lockfile.sh:101", got[0][1])

    def test_coreutils_may_go_undeclared(self):
        check = {"name": "x", "command": "mkdir -p a/b && just clippy",
                 "tools": ["just"]}
        self.assertEqual(dt.undeclared_for_check(check, self.REPO), [])

    def test_a_non_coreutils_program_in_an_inline_command_is_reported(self):
        # sed/grep/awk are separate Debian packages, which is the whole reason
        # check-lockfile.sh's sed needed declaring.
        check = {"name": "x", "command": "cargo build | sed 's/a/b/'", "tools": ["cargo"]}
        got = dt.undeclared_for_check(check, self.REPO)
        self.assertEqual([n for n, _ in got], ["sed"])

    def test_every_committed_check_is_clean(self):
        import yaml
        data = yaml.safe_load((SCRIPTS.parent / "checks.yaml").read_text())
        for c in data["checks"]:
            self.assertEqual(
                dt.undeclared_for_check(c, self.REPO), [],
                f"{c['name']} invokes something it does not declare")


if __name__ == "__main__":
    unittest.main()
