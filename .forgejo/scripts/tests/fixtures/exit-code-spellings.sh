#!/usr/bin/env bash
# NOT a real script and never executed. It exists so test-exit-codes-registry.sh
# can prove its discovery sees every spelling it claims to, and can state
# exactly where that discovery is imprecise -- one allocation per recognised
# spelling, plus decoys whose treatment is asserted rather than assumed.
#
# The codes here (91, 92, 94) are all inside the scanned 9x range and none is
# allocated anywhere in .forgejo/scripts, so this file can never be mistaken
# for a real allocation if it is ever scanned by accident.
refuse() { echo "$1" >&2; exit "$2"; }

# spelling 1: the literal bash exit
exit 91

# spelling 2: a refusal helper taking the code as its last argument
[ -f /nonexistent ] || refuse "nothing to examine" 92

# decoy A -- a whole-line comment. Must NOT be discovered: comments are where
# this file's own prose discusses codes, and a scanner that read them would
# demand a registry row for every code anyone ever mentioned. Discovery drops
# whole-line comments before matching, so `exit 93` here is invisible, and so
# is a prose mention of refuse "..." 93.

# decoy B -- a 9x inside a command's argument. This IS discovered, and that is
# a known imprecision, declared rather than hidden. It errs toward demanding a
# registry row for something that is not an allocation: a loud false alarm a
# human resolves in seconds. The opposite error -- a real allocation going
# unseen -- is the one this whole file exists to prevent, and it is silent.
grep -q "exit 94" /dev/null
