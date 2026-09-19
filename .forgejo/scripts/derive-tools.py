#!/usr/bin/env python3
"""Derive the external programs a shell script invokes, in command position.

WHY THIS EXISTS AS A SCRIPT RATHER THAN A ONE-OFF SWEEP. The tools gate in
run-check.sh reports the tools a check DECLARES and finds missing. It can
never report a tool that was never declared -- so an undeclared tool does not
refuse with 97, it dies with a bare 127 in the ordinary range, where nothing
separates our missing tool from upstream's verdict on our code. No CI run can
find this class. Only reading can, and reading does not scale or repeat.

WHY IT IS FIXTURE-DRIVEN, which matters more than the parser. Three hand-rolled
sweeps preceded this file. Each produced a confident answer and two were wrong,
in OPPOSITE directions:

  - a regex that stripped heredocs swallowed real code with them, and missed
    check-lockfile.sh's `echo "$missing" | sed ...` -- a FALSE NEGATIVE that
    looked like a clean result, because a sweep that sees less reports less.
  - a grep that skipped comment stripping reported `jq` and `just` for
    schema-compat, where both appear only in prose explaining that the script
    was rewritten to STOP using them -- a FALSE POSITIVE.

Both were caught by opening the file and reading the cited lines. So the fixture
(tests/fixtures/tool-invocations.sh) states the expected answer independently of
this implementation, and contains one case for each way the earlier attempts
failed. A deriver validated only against the scripts it was written from would
agree with itself and prove nothing.

SCOPE, deliberately narrow. This answers "what does this script call", not "what
is installed" -- that is the tools gate's job, at run time, where the check runs.
"""
import re
import sys

# Shell keywords, builtins, and constructs that are never external programs.
BUILTINS = set("""
if then else elif fi for while until do done case esac function select
cd test echo printf read set unset export local declare typeset readonly
return exit shift eval exec source trap wait times let true false
break continue alias unalias getopts hash pwd umask ulimit jobs fg bg kill
""".split())
BUILTINS.add("command")
BUILTINS.add("[")
BUILTINS.add("[[")
BUILTINS.add(".")
BUILTINS.add(":")

# Separators after which a new command begins.
_SEP = re.compile(r"(?:\|\||&&|[|;&])")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
# A plausible program name. Paths are handled by the caller (validate-checks.py
# already resolves repo-relative command paths); here we want bare names.
_NAME = re.compile(r"^[a-z_][a-z0-9._-]*$", re.I)
# A function DEFINED in the same script is not an external tool. Without this,
# check-schema-compat.sh's own `say`, `refuse` and `generate` helpers read as
# three missing programs -- and a tools list "corrected" to declare them would
# make the run-time gate demand binaries that never existed.
_FUNCDEF = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*\)", re.M)


def strip_shell_noise(text):
    """Return `text` with comments, quoted strings and heredoc BODIES removed,
    preserving line structure so reported line numbers stay true.

    Done as a character scan rather than regexes on purpose. The regex attempt
    that this replaces used `.*?\\n.*?\\n\\s*DELIM` under DOTALL to drop
    heredocs; with several heredocs in one file that pattern spans from the
    first to a later one and deletes everything between, which is how a real
    `| sed ...` disappeared and the sweep came back clean.
    """
    out_lines = []
    heredoc_delim = None
    # Quote state is carried ACROSS lines, because a shell string does span
    # them. Resetting it per line made every line of a multi-line refusal
    # message read as commands, which is why an early run of this deriver
    # "found" programs called `refuse`, `would` and `Tracked` -- ordinary
    # English from inside `echo "..."` blocks several lines long.
    quote = None
    for raw in text.split("\n"):
        # Inside a heredoc body: emit a blank line until the delimiter.
        if heredoc_delim is not None:
            if raw.strip() == heredoc_delim:
                heredoc_delim = None
            out_lines.append("")
            continue

        # ONE scan producing TWO strings, because heredoc detection and command
        # extraction need different amounts stripped, and each ordering on its
        # own is wrong in a different direction. The fixture caught both:
        #
        #   detect on the string-stripped line -> `cat <<'EOF'` becomes a bare
        #     `cat <<`, the delimiter is gone, and the BODY reads as commands.
        #   detect on the raw line             -> a COMMENT that merely writes
        #     `<<'EOF'` while explaining this opens a heredoc that never ends,
        #     swallowing the rest of the file. (This comment did exactly that.)
        #
        # So: `nocomment` keeps quotes and drops comments -- the right input for
        # finding a delimiter. `line` drops both -- the right input for finding
        # commands.
        nocomment = []
        line = []
        i = 0
        n = len(raw)
        while i < n:
            ch = raw[i]
            if quote:
                # Inside a string: everything is data. Backslash escapes only
                # apply in double quotes.
                nocomment.append(ch)
                if quote == '"' and ch == "\\" and i + 1 < n:
                    nocomment.append(raw[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            if ch == "\\" and i + 1 < n:
                nocomment.append(ch)
                nocomment.append(raw[i + 1])
                i += 2
                continue
            if ch in "\"'":
                quote = ch
                nocomment.append(ch)
                i += 1
                continue
            if ch == "#":
                # A comment only when it starts a word, never mid-token
                # (so `foo#bar` and `${x#y}` survive).
                if not line or line[-1] in " \t;|&(":
                    break
            nocomment.append(ch)
            line.append(ch)
            i += 1

        cur = "".join(nocomment)
        opened = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", cur)
        if opened and "<<<" not in cur:
            heredoc_delim = opened.group(1)

        out_lines.append("".join(line))
    return "\n".join(out_lines)


def invocations(text):
    """Programs invoked in command position, as {name: first line number}.

    Excludes shell functions the script defines itself.
    """
    found = {}
    cleaned = strip_shell_noise(text)
    local_funcs = set(_FUNCDEF.findall(cleaned))
    for lineno, line in enumerate(cleaned.split("\n"), 1):
        # `$(...)` and backticks open a command position too; treat their
        # contents as ordinary segments.
        line = line.replace("$(", "\n").replace("`", "\n").replace(")", "\n")
        for chunk in line.split("\n"):
            for seg in _SEP.split(chunk):
                toks = seg.strip().split()
                k = 0
                # Skip leading VAR=value assignments: `SOURCE_DATE_EPOCH=0 cargo build`
                while k < len(toks) and _ASSIGN.match(toks[k]):
                    k += 1
                if k >= len(toks):
                    continue
                name = toks[k]
                if name.startswith(("-", "$", "(", "{")):
                    continue
                if "/" in name:          # a path: the caller resolves these
                    continue
                if name in BUILTINS or name in local_funcs:
                    continue
                if not _NAME.match(name):
                    continue
                found.setdefault(name, lineno)
    return found


# Programs a check may invoke WITHOUT declaring them. This is the convention
# runcove-tbxh names: coreutils goes undeclared, and anything else does not.
#
# It is a hand-maintained list, which this arc distrusts on principle -- so
# note what makes this one different from the per-check lists it guards. Those
# drift because they describe OUR scripts, which change every week. This
# describes Debian's coreutils package, which does not, and it is checkable
# against any Debian base image with one command. It is also fail-LOUD rather
# than fail-open: a program wrongly missing from here produces a refusal
# naming a real file and line, which someone reads and fixes, not a silent pass.
#
# Taken from the coreutils package itself, not from memory. `bash`/`sh` are
# here as the interpreter, and `sed`/`grep`/`awk` are deliberately NOT: they
# are separate Debian packages, which is exactly why check-lockfile.sh's sed
# had to be declared.
ALWAYS_PRESENT = set("""
arch b2sum base32 base64 basename basenc cat chcon chgrp chmod chown chroot
cksum comm cp csplit cut date dd df dir dircolors dirname du echo env expand
expr factor false fmt fold groups head hostid id install join link ln logname
ls md5sum mkdir mkfifo mknod mktemp mv nice nl nohup nproc numfmt od paste
pathchk pinky pr printenv printf ptx pwd readlink realpath rm rmdir runcon
seq sha1sum sha224sum sha256sum sha384sum sha512sum shred shuf sleep sort
split stat stdbuf stty sum sync tac tail tee test timeout touch tr true
truncate tsort tty uname unexpand uniq unlink users vdir wc who whoami yes
bash sh
""".split())


def undeclared_for_check(check, repo_root):
    """[(program, where)] a check invokes but does not declare.

    Looks at the check's own `command` AND any repo script that command runs,
    because both are places a tool requirement hides. Skips anything in
    ALWAYS_PRESENT, any shell function the script defines, and the scripts
    themselves.
    """
    import os
    declared = set(check.get("tools") or [])
    sources = [("<command>", check["command"])]
    sibs = set()
    for tok in re.findall(r"[\w./-]+", check["command"]):
        if tok.endswith((".sh", ".py")):
            path = os.path.join(repo_root, tok)
            if os.path.isfile(path):
                sibs.add(os.path.basename(tok))
                with open(path) as fh:
                    sources.append((tok, fh.read()))

    out = []
    seen = set()
    for where, text in sources:
        for name, lineno in sorted(invocations(text).items(), key=lambda kv: kv[1]):
            if name in declared or name in ALWAYS_PRESENT or name in sibs:
                continue
            if name in seen:
                continue
            seen.add(name)
            out.append((name, f"{where}:{lineno}"))
    return out


def main(argv):
    if len(argv) < 2:
        print("usage: derive-tools.py <script> [<script>...]", file=sys.stderr)
        return 2
    for path in argv[1:]:
        with open(path) as fh:
            got = invocations(fh.read())
        for name in sorted(got):
            print(f"{path}:{got[name]}:{name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
