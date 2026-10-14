"""Rule-test runner, MITRE coverage aggregation, and report generation."""
from detection_as_code.pipeline import (build_report, mitre_coverage,
                                        report_markdown, run_rule_tests)
from detection_as_code.rules import load_rules, validate_ruleset


def test_bundled_rule_tests_all_pass():
    results = run_rule_tests(load_rules())
    assert results, "expected bundled rules to carry tests"
    assert all(r["passed"] for r in results), [r for r in results if not r["passed"]]


def test_runner_reports_a_wrong_expectation_as_fail():
    rule = {"id": "x",
            "detection": {"selection": {"a": 1}, "condition": "selection"},
            "tests": [{"name": "wrong", "event": {"a": 1}, "should_match": False}]}
    results = run_rule_tests([rule])
    assert results[0]["passed"] is False
    assert results[0]["actual"] is True


def test_runner_handles_broken_rule_without_crashing():
    rule = {"id": "boom",
            "detection": {"selection": {"a": 1}, "condition": "selection and ghost"},
            "tests": [{"name": "t", "event": {"a": 1}, "should_match": True}]}
    results = run_rule_tests([rule])
    assert results[0]["passed"] is False
    assert results[0]["error"]


def test_mitre_coverage_aggregates():
    rules = [
        {"id": "r1", "mitre": {"tactic": "Execution", "technique": "T1059.001"}},
        {"id": "r2", "mitre": {"tactic": "Execution", "technique": "T1203"}},
        {"id": "r3", "mitre": {"tactic": "Exfiltration", "technique": "T1567.002"}},
    ]
    cov = mitre_coverage(rules)
    assert cov["tactics"]["Execution"] == ["T1059.001", "T1203"]
    assert set(cov["techniques"]) == {"T1059.001", "T1203", "T1567.002"}
    assert cov["techniques"]["T1203"] == ["r2"]


def test_build_report_summary_and_gate():
    rules = load_rules()
    issues = validate_ruleset(rules)
    results = run_rule_tests(rules)
    cov = mitre_coverage(rules)
    report = build_report(rules, issues, results, cov)
    s = report["summary"]
    assert s["rules"] == len(rules)
    assert s["tests_total"] == len(results)
    assert s["ci_pass"] is True  # bundled ruleset is clean and green


def test_report_gate_fails_on_error():
    rules = [{"id": "bad", "title": "x", "severity": "high",
              "logsource": {}, "mitre": {"tactic": "T", "technique": "T1110"},
              "detection": {"condition": "sel"}}]  # no selections -> error
    issues = validate_ruleset(rules)
    report = build_report(rules, issues, run_rule_tests(rules), mitre_coverage(rules))
    assert report["summary"]["ci_pass"] is False
    assert report["summary"]["lint_errors"] >= 1


def test_report_markdown_has_headers():
    rules = load_rules()
    report = build_report(rules, validate_ruleset(rules),
                          run_rule_tests(rules), mitre_coverage(rules))
    md = report_markdown(report)
    assert "# Detection-as-Code Pipeline Report" in md
    assert "MITRE ATT&CK coverage" in md
    assert "deterministic" in md  # honesty: report is not AI-generated
