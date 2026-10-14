"""The CI pipeline pieces: run each rule's bundled tests, aggregate MITRE
coverage, and build the markdown + JSON report. All deterministic, no LLM.
"""
from __future__ import annotations

import datetime as _dt

from .matcher import match


def run_rule_tests(rules):
    """Run every rule's bundled ``tests`` through the matcher.

    Each rule carries sample events labelled should-match / should-not-match;
    we assert the matcher's verdict equals the label. These are unit tests for
    detections. Returns a list of result dicts.
    """
    results = []
    for rule in rules:
        for test in rule.get("tests") or []:
            if not isinstance(test, dict) or "event" not in test or "should_match" not in test:
                continue  # malformed; the linter already warns
            expected = bool(test["should_match"])
            try:
                actual = match(rule, test["event"])
                error = None
            except Exception as exc:  # a broken rule shouldn't crash the runner
                actual, error = None, str(exc)
            results.append({
                "rule_id": rule.get("id"),
                "test": test.get("name", "unnamed test"),
                "expected": expected,
                "actual": actual,
                "passed": actual == expected,
                "error": error,
            })
    return results


def mitre_coverage(rules):
    """Aggregate which ATT&CK tactics/techniques the ruleset covers."""
    tactics = {}      # tactic -> set of technique ids
    techniques = {}   # technique id -> list of rule ids
    for rule in rules:
        mitre = rule.get("mitre")
        if not isinstance(mitre, dict):
            continue
        tactic, technique = mitre.get("tactic"), mitre.get("technique")
        if tactic and technique:
            tactics.setdefault(tactic, set()).add(str(technique))
            techniques.setdefault(str(technique), []).append(rule.get("id"))
    return {
        "tactics": {t: sorted(v) for t, v in sorted(tactics.items())},
        "techniques": {k: techniques[k] for k in sorted(techniques)},
    }


def build_report(rules, issues, test_results, coverage):
    """Assemble the machine-readable report (also the source for markdown)."""
    errors = [i for i in issues if i[1] == "error"]
    warnings = [i for i in issues if i[1] == "warn"]
    failed = [r for r in test_results if not r["passed"]]
    summary = {
        "rules": len(rules),
        "lint_errors": len(errors),
        "lint_warnings": len(warnings),
        "tests_total": len(test_results),
        "tests_passed": len(test_results) - len(failed),
        "tests_failed": len(failed),
        "tactics_covered": len(coverage["tactics"]),
        "techniques_covered": len(coverage["techniques"]),
        "ci_pass": not errors and not failed,
    }
    return {
        "generated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "summary": summary,
        "lint": [{"rule_id": r, "level": lvl, "message": m} for r, lvl, m in issues],
        "tests": test_results,
        "coverage": coverage,
    }


def report_markdown(report):
    """Render the report dict as a readable markdown document."""
    s = report["summary"]
    status = "PASS" if s["ci_pass"] else "FAIL"
    out = []
    out.append("# Detection-as-Code Pipeline Report")
    out.append("")
    out.append("_Generated %s. This report is deterministic (no AI involved)._"
               % report["generated_at"])
    out.append("")
    out.append("## Gate: **%s**" % status)
    out.append("")
    out.append("| Metric | Value |")
    out.append("| --- | --- |")
    out.append("| Rules | %d |" % s["rules"])
    out.append("| Lint errors | %d |" % s["lint_errors"])
    out.append("| Lint warnings | %d |" % s["lint_warnings"])
    out.append("| Rule tests passed | %d / %d |" % (s["tests_passed"], s["tests_total"]))
    out.append("| MITRE tactics covered | %d |" % s["tactics_covered"])
    out.append("| MITRE techniques covered | %d |" % s["techniques_covered"])
    out.append("")

    if report["lint"]:
        out.append("## Lint findings")
        out.append("")
        for item in report["lint"]:
            out.append("- **%s** [%s] `%s`: %s"
                       % (item["level"].upper(), item["rule_id"], item["rule_id"], item["message"]))
        out.append("")

    out.append("## Rule tests")
    out.append("")
    for r in report["tests"]:
        mark = "ok" if r["passed"] else "FAIL"
        extra = " (error: %s)" % r["error"] if r["error"] else ""
        out.append("- [%s] `%s` — %s (expected=%s actual=%s)%s"
                   % (mark, r["rule_id"], r["test"], r["expected"], r["actual"], extra))
    out.append("")

    out.append("## MITRE ATT&CK coverage")
    out.append("")
    cov = report["coverage"]
    if not cov["tactics"]:
        out.append("_No coverage mapped._")
    else:
        for tactic, techs in cov["tactics"].items():
            out.append("- **%s**: %s" % (tactic, ", ".join(techs)))
    out.append("")
    return "\n".join(out)
