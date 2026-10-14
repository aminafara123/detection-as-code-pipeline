"""Validator/linter: bundled rules pass; several broken rules each get caught."""
import copy

from detection_as_code.rules import (errors_only, load_rules, validate_rule,
                                      validate_ruleset)


def _good():
    return {
        "id": "demo-rule",
        "title": "Demo",
        "severity": "high",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {"selection": {"event_id": 4625}, "condition": "selection"},
        "mitre": {"tactic": "Credential Access", "technique": "T1110"},
        "false_positives": ["something"],
        "tests": [{"name": "t", "event": {"event_id": 4625}, "should_match": True}],
    }


def _messages(rule):
    return " ".join(m for _, _, m in validate_rule(rule))


def test_bundled_rules_are_clean():
    rules = load_rules()
    assert len(rules) >= 5
    assert errors_only(validate_ruleset(rules)) == []


def test_good_rule_passes():
    assert errors_only(validate_rule(_good())) == []


def test_missing_required_field_caught():
    r = _good()
    del r["title"]
    assert "missing required field: title" in _messages(r)


def test_bad_severity_caught():
    r = _good()
    r["severity"] = "super-duper"
    assert "invalid severity" in _messages(r)


def test_missing_mitre_technique_caught():
    r = _good()
    r["mitre"] = {"tactic": "Execution"}
    assert "mitre.technique is required" in _messages(r)


def test_bad_technique_id_caught():
    r = _good()
    r["mitre"]["technique"] = "1110"  # missing the T####
    assert "not a valid ATT&CK id" in _messages(r)


def test_unknown_operator_caught():
    r = _good()
    r["detection"]["selection"] = {"event_id|bogus": 4625}
    assert "unknown operator" in _messages(r)


def test_invalid_regex_caught():
    r = _good()
    r["detection"]["selection"] = {"user|re": "([unclosed"}
    assert "invalid regex" in _messages(r)


def test_condition_undefined_selection_caught():
    r = _good()
    r["detection"]["condition"] = "selection and ghost"
    assert "undefined selection" in _messages(r)


def test_no_selections_caught():
    r = _good()
    r["detection"] = {"condition": "all of them"}
    assert "no selections" in _messages(r)


def test_duplicate_ids_caught():
    a, b = _good(), _good()
    a["_path"], b["_path"] = "a.yml", "b.yml"
    issues = validate_ruleset([a, b])
    assert any("duplicate id" in m for _, lvl, m in issues if lvl == "error")


def test_malformed_test_is_a_warning_not_error():
    r = _good()
    r["tests"] = [{"name": "bad"}]  # no event / should_match
    issues = validate_rule(r)
    assert errors_only(issues) == []
    assert any(lvl == "warn" for _, lvl, _ in issues)
