#!/usr/bin/env bash
# FIXTURE for derive-tools.py. Not executed; read as text.
#
# The expected answer is fixed HERE, before the deriver exists, because the
# three hand-rolled sweeps that preceded it each produced a confident answer
# and two were wrong in OPPOSITE directions: a regex that stripped heredocs
# swallowed real code and under-reported, and a grep that skipped comment
# stripping over-reported words out of prose. A deriver checked only against
# the scripts it was written from would agree with itself either way.
#
# EXPECTED, exactly: banana cat cherry damson elderberry fig grape
# NOT expected:      apricot (comment), blackcurrant/blueberry (string data),
#                    cloudberry (heredoc body), EOF (a delimiter, not a
#                    command), date (assignment RHS), honeydew (a function
#                    defined in this very file), if/then/for/local/return
#                    (builtins and keywords)
#
# `cat` IS expected, and the correction is worth keeping: this list first said
# it was not, because the heredoc case was written thinking about the body
# rather than the line that opens it. `cat <<'EOF'` really does invoke cat. The
# fixture was wrong and the deriver was right -- which is the argument for
# writing the expectation down where it can be disagreed with, instead of
# reading it off whatever the code happened to print.

# apricot --version          <- a whole-line comment: NEVER a finding. This is
#                               the false positive that made sweep 3 wrong.

bananas=1                    # an assignment, not the program `bananas`
banana --check               # EXPECTED: plain command at line start

echo "blackcurrant is not invoked here"   # string DATA, not a command
echo 'blueberry --force'                  # single-quoted DATA too

# A pipeline. THE CASE THAT MATTERS: this is the shape of check-lockfile.sh's
# `echo "$missing" | sed 's/^/  /'`, the real undeclared tool that started
# this, and precisely what sweep 2 deleted along with the heredoc it was
# trying to strip.
echo "$missing" | cherry 's/^/  /'

# After && and ; and inside $( ) -- all still command position.
damson --quiet && elderberry --list
found=$(fig --print)
grape --run; true

DATE_CMD=date                # assignment RHS: `date` is a VALUE here, not a call

cat <<'EOF'
cloudberry --this-is-inside-a-heredoc
EOF

if [ -n "$found" ]; then
  return 0
fi

# A function DEFINED here is not an external tool. check-schema-compat.sh's
# own say/refuse/generate helpers were reported as three missing programs
# before this case existed, and "fixing" the tools list to declare them would
# have made the run-time gate demand binaries that never existed.
honeydew() { echo "a local helper"; }
honeydew --called-here          # NOT expected: defined just above
