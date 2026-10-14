"""CLI for detection-as-code-pipeline.

    detection-as-code lint                 # validate rules (CI gate)
    detection-as-code test                 # run each rule's bundled unit tests
    detection-as-code pipeline [-o DIR]    # lint + test + coverage + write report
    detection-as-code scan --events F.json # run all rules over events -> alerts
    detection-as-code draft "<english>"    # AI-draft a rule skeleton (local LLM)

All commands default to the bundled rules; pass --rules DIR to point elsewhere.
Only `draft` touches the LLM; everything else is fully offline.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from . import llm
from .matcher import match
from .pipeline import (build_report, mitre_coverage, report_markdown,
                       run_rule_tests)
from .rules import default_rules_dir, errors_only, load_rules, validate_ruleset

AI_LABEL = (
    "# >>> AI-GENERATED DRAFT - advisory only. A human MUST review, test, and\n"
    "# >>> tune this before committing. The matcher/validator do NOT use AI.\n"
)

_DRAFT_SYSTEM = """You are a senior detection engineer. Output ONLY a single YAML \
detection rule, no prose, no code fences. Use exactly this schema:

id: short-kebab-id
title: Human Title
severity: one of informational|low|medium|high|critical
description: one line
logsource:
  product: e.g. windows
  service: e.g. security
detection:
  selection:
    field: value                 # equals
    other|contains: value        # operators: contains, startswith, re, in
  condition: selection           # combine names with and/or/not, or "all of them"
mitre:
  tactic: ATT&CK tactic name
  technique: a T#### id (optionally .### )
false_positives:
  - a realistic benign cause
tests:
  - name: should match
    event: {field: value}
    should_match: true
  - name: should not match
    event: {field: other}
    should_match: false
"""


def _print_issues(issues):
    for rid, level, msg in issues:
        print("  [%s] %s: %s" % (level.upper(), rid, msg), file=sys.stderr)


def draft_rule(description):
    """Ask the local LLM for a rule skeleton. Returns AI-labelled YAML text."""
    content = llm.complete("Write a detection rule for: " + description,
                           system=_DRAFT_SYSTEM)
    return AI_LABEL + content.strip() + "\n"


def _load(args):
    return load_rules(args.rules)


def cmd_lint(args):
    rules = _load(args)
    issues = validate_ruleset(rules)
    errors = errors_only(issues)
    if issues:
        _print_issues(issues)
    print("lint: %d rule(s), %d error(s), %d warning(s)"
          % (len(rules), len(errors), len(issues) - len(errors)))
    return 1 if errors else 0


def cmd_test(args):
    rules = _load(args)
    results = run_rule_tests(rules)
    failed = [r for r in results if not r["passed"]]
    for r in failed:
        print("  FAIL %s / %s (expected=%s actual=%s)"
              % (r["rule_id"], r["test"], r["expected"], r["actual"]), file=sys.stderr)
    print("rule-tests: %d passed, %d failed" % (len(results) - len(failed), len(failed)))
    return 1 if failed else 0


def cmd_pipeline(args):
    rules = _load(args)
    issues = validate_ruleset(rules)
    results = run_rule_tests(rules)
    coverage = mitre_coverage(rules)
    report = build_report(rules, issues, results, coverage)

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(report_markdown(report), encoding="utf-8")

    s = report["summary"]
    print("pipeline: %d rules | %d lint errors | %d/%d tests passed | "
          "%d tactics, %d techniques covered"
          % (s["rules"], s["lint_errors"], s["tests_passed"], s["tests_total"],
             s["tactics_covered"], s["techniques_covered"]))
    print("gate: %s  (report -> %s)" % ("PASS" if s["ci_pass"] else "FAIL", out_dir))
    return 0 if s["ci_pass"] else 1


def cmd_scan(args):
    rules = _load(args)
    events = json.loads(pathlib.Path(args.events).read_text(encoding="utf-8"))
    if isinstance(events, dict):
        events = [events]
    alerts = 0
    for i, event in enumerate(events):
        for rule in rules:
            try:
                hit = match(rule, event)
            except Exception:
                hit = False
            if hit:
                alerts += 1
                mitre = rule.get("mitre") or {}
                print("ALERT event#%d  [%s] %s  (%s %s)"
                      % (i, str(rule.get("severity")).upper(), rule.get("title"),
                         mitre.get("tactic"), mitre.get("technique")))
    print("scan: %d event(s), %d alert(s)" % (len(events), alerts))
    return 0


def cmd_draft(args):
    try:
        print(draft_rule(args.description))
    except llm.LLMError as exc:
        print("LLM unavailable: %s" % exc, file=sys.stderr)
        print("Start ollama (or set LLM_BASE_URL) and retry. The rest of the "
              "pipeline works offline without it.", file=sys.stderr)
        return 2
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="detection-as-code",
        description="Detection-as-code: lint, unit-test, and CI-gate SIEM rules.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_rules_arg(p):
        p.add_argument("--rules", default=str(default_rules_dir()),
                       help="rules directory (default: bundled rules)")

    p = sub.add_parser("lint", help="validate rules (CI gate)")
    add_rules_arg(p)
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("test", help="run each rule's bundled unit tests")
    add_rules_arg(p)
    p.set_defaults(func=cmd_test)

    p = sub.add_parser("pipeline", help="lint + test + coverage + write report")
    add_rules_arg(p)
    p.add_argument("-o", "--out", default="reports", help="report output dir")
    p.set_defaults(func=cmd_pipeline)

    p = sub.add_parser("scan", help="run all rules over an events JSON file")
    add_rules_arg(p)
    p.add_argument("--events", default=str(pathlib.Path(default_rules_dir()).parent
                                           / "sample_events.json"),
                   help="JSON file: a list of event objects")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("draft", help="AI-draft a rule skeleton (uses local LLM)")
    p.add_argument("description", help="plain-English description of the detection")
    p.set_defaults(func=cmd_draft)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
