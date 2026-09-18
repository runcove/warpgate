"""Load and validate .forgejo/checks.yaml — the translation of upstream's CI.

Pure: reads one file, returns data or raises. No subprocesses, no network.
"""
import datetime
import yaml

STATES = ("reporting", "blocking", "excepted")
REQUIRED = ("name", "upstream", "command", "compiles", "state")
UPSTREAM_TAG = "v0.28.6"


def load(path):
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or "checks" not in doc:
        raise ValueError(f"{path}: top level must be a mapping with a 'checks' key")
    checks = doc["checks"]
    if not isinstance(checks, list) or not checks:
        raise ValueError(f"{path}: 'checks' must be a non-empty list")

    seen = set()
    for raw in checks:
        name = raw.get("name", "<unnamed>")
        for key in REQUIRED:
            if key not in raw:
                raise ValueError(f"check {name!r}: missing required key {key!r}")
        if name in seen:
            raise ValueError(f"check {name!r}: duplicate name")
        seen.add(name)

        if raw["state"] not in STATES:
            raise ValueError(
                f"check {name!r}: state {raw['state']!r} is not one of {STATES}")
        if raw["compiles"] not in (True, False, "unverified"):
            raise ValueError(
                f"check {name!r}: compiles must be true, false, or 'unverified'")

        if raw["state"] == "excepted":
            if not raw.get("reason"):
                raise ValueError(
                    f"check {name!r}: state 'excepted' requires a 'reason'. "
                    "An exception nobody wrote a reason for is a disabled check.")
            if "review_by" not in raw:
                raise ValueError(
                    f"check {name!r}: state 'excepted' requires 'review_by'. "
                    "An exception with no end date never ends.")
            if not isinstance(raw["review_by"], datetime.date):
                raise ValueError(
                    f"check {name!r}: review_by must be a date (YYYY-MM-DD)")
    return checks


def upstream_tag(path):
    with open(path) as fh:
        doc = yaml.safe_load(fh)
    tag = doc.get("upstream_tag")
    if not tag:
        raise ValueError(f"{path}: 'upstream_tag' is required")
    return tag


def compiles_token(check):
    """Return the check's `compiles` field as the exact lowercase string a
    shell consumer should compare against: "true", "false", or "unverified".

    Deliberately not `str(bool(...))` — that gives "True"/"False" and a shell
    `[ "$compiles" = "true" ]` check silently never matches, so a compiling
    check would run uncapped instead of under its memory/CPU cap. This is the
    one place that translation happens, so every caller gets it right by
    construction.
    """
    value = check["compiles"]
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value == "unverified":
        return "unverified"
    raise ValueError(f"compiles must be true, false, or 'unverified', got {value!r}")
