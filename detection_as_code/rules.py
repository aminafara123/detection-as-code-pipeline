"""Load detection rules from YAML and lint them (the CI gate's validator).

An "issue" is a tuple ``(rule_id, level, message)`` where level is "error" or
"warn". Any error means the ruleset fails the gate.
"""
from __future__ import annotations

import pathlib
import re

import yaml

from .matcher import parse_key, referenced_selections

REQUIRED_FIELDS = ["id", "title", "severity", "logsource", "detection", "mitre"]
VALID_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")  # T1110 or T1567.002


def default_rules_dir():
    return pathlib.Path(__file__).parent / "rules"


def load_rules(rules_dir=None):
    """Parse every *.yml / *.yaml under ``rules_dir`` (bundled dir by default).

    Each rule dict gets a ``_path`` key for error messages. Raises yaml errors
    only on genuinely unparseable files; everything else is caught by the linter.
    """
    directory = pathlib.Path(rules_dir) if rules_dir else default_rules_dir()
    rules = []
    for path in sorted(directory.glob("*.y*ml")):
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            data = {"id": None, "_parse_error": "file is not a YAML mapping"}
        data["_path"] = str(path)
        rules.append(data)
    return rules


def validate_rule(rule):
    """Lint a single rule. Returns a list of issue tuples."""
    issues = []
    rid = rule.get("id") or "<no id>"

    def err(msg):
        issues.append((rid, "error", msg))

    if rule.get("_parse_error"):
        err(rule["_parse_error"])
        return issues

    for field in REQUIRED_FIELDS:
        if rule.get(field) in (None, "", {}, []):
            err("missing required field: %s" % field)

    sev = rule.get("severity")
    if sev is not None and str(sev).lower() not in VALID_SEVERITIES:
        err("invalid severity %r (allowed: %s)"
            % (sev, ", ".join(sorted(VALID_SEVERITIES))))

    mitre = rule.get("mitre")
    if isinstance(mitre, dict):
        if not mitre.get("tactic"):
            err("mitre.tactic is required")
        technique = mitre.get("technique")
        if not technique:
            err("mitre.technique is required")
        elif not TECHNIQUE_RE.match(str(technique)):
            err("mitre.technique %r is not a valid ATT&CK id (e.g. T1110, T1567.002)"
                % technique)
    elif mitre is not None:
        err("mitre must be a mapping with tactic + technique")

    detection = rule.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        err("detection block must be a mapping containing a 'condition'")
        return issues  # nothing else is checkable

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        err("detection block has no selections")

    for name, sel in selections.items():
        if not isinstance(sel, dict):
            err("selection %r must be a mapping of field tests" % name)
            continue
        for key, value in sel.items():
            try:
                _, op = parse_key(key)
            except ValueError as exc:
                err(str(exc))
                continue
            if op == "regex":
                for pattern in (value if isinstance(value, list) else [value]):
                    try:
                        re.compile(str(pattern))
                    except re.error as exc:
                        err("invalid regex in %r: %s" % (key, exc))

    try:
        for ref in referenced_selections(detection["condition"]):
            if ref not in selections:
                err("condition references undefined selection %r" % ref)
    except ValueError as exc:
        err("bad condition %r: %s" % (detection.get("condition"), exc))

    for i, test in enumerate(rule.get("tests") or []):
        if not isinstance(test, dict) or "event" not in test or "should_match" not in test:
            issues.append((rid, "warn", "test #%d missing 'event' or 'should_match'" % i))

    return issues


def validate_ruleset(rules):
    """Lint every rule plus cross-rule checks (unique ids)."""
    issues = []
    for rule in rules:
        issues.extend(validate_rule(rule))

    by_id = {}
    for rule in rules:
        rid = rule.get("id")
        if rid is not None:
            by_id.setdefault(rid, []).append(rule.get("_path", "?"))
    for rid, paths in by_id.items():
        if len(paths) > 1:
            issues.append((rid, "error", "duplicate id used by: %s" % ", ".join(paths)))

    return issues


def errors_only(issues):
    return [i for i in issues if i[1] == "error"]
