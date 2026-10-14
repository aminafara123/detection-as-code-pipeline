"""Deterministic detection matcher: does one log event trigger one rule?

This is the core of the project and has NO LLM and NO network. Given a rule's
``detection`` block and a single event dict, decide match / no-match.

Schema (Sigma-inspired, our own small documented subset):

    detection:
      <selection_name>:
        <field>: value            # equals   (string compare, case-insensitive)
        <field>|contains: value   # substring
        <field>|startswith: value # prefix
        <field>|re: pattern       # regex (re.search, case-sensitive as written)
        <field>|in: [a, b, c]     # value in list
      condition: <expr>

A selection matches when ALL of its field tests match (AND within a selection).
A field value given as a list is an OR over the values (any match => field ok).
The ``condition`` combines selection names with ``and`` / ``or`` / ``not`` and
parentheses, or the shortcuts ``all of them`` / ``any of them``.

ponytail: single-event matcher only. No correlation, aggregation, counting, or
time windows across events -- that belongs in the SIEM, not the rule syntax.
ponytail: condition grammar is and/or/not + parens + "all/any of them". No
"1 of them", no "all of selection*" prefixes. Add if a rule ever needs them.
"""
from __future__ import annotations

import re

# --- field operators ---------------------------------------------------------
# Canonical op name -> comparison function(event_value, expected_value) -> bool.


def _s(v):
    return "" if v is None else str(v)


def _op_equals(ev, exp):
    return _s(ev).lower() == _s(exp).lower()


def _op_contains(ev, exp):
    return _s(exp).lower() in _s(ev).lower()


def _op_startswith(ev, exp):
    return _s(ev).lower().startswith(_s(exp).lower())


def _op_regex(ev, exp):
    return re.search(str(exp), _s(ev)) is not None


OPS = {
    "equals": _op_equals,
    "contains": _op_contains,
    "startswith": _op_startswith,
    "regex": _op_regex,
}

# Modifier found after "|" in a field key -> canonical op name. None == bare key.
_OP_ALIASES = {
    None: "equals",
    "equals": "equals",
    "contains": "contains",
    "startswith": "startswith",
    "re": "regex",
    "regex": "regex",
    "in": "in",
}


def parse_key(key):
    """Split "field|mod" into (field, canonical_op). Raise ValueError if unknown."""
    if "|" in key:
        field, _, mod = key.partition("|")
        mod = mod.strip().lower()
    else:
        field, mod = key, None
    if mod not in _OP_ALIASES:
        raise ValueError("unknown operator %r in field %r" % (mod, key))
    return field, _OP_ALIASES[mod]


def _match_field(event, key, expected):
    field, op = parse_key(key)
    ev = event.get(field)
    if op == "in":
        values = expected if isinstance(expected, list) else [expected]
        return any(_op_equals(ev, x) for x in values)
    fn = OPS[op]
    if isinstance(expected, list):  # list => OR over the values
        return any(fn(ev, x) for x in expected)
    return fn(ev, expected)


def match_selection(event, selection):
    """True when every field test in the selection matches the event (AND)."""
    for key, expected in selection.items():
        if not _match_field(event, key, expected):
            return False
    return True


# --- condition grammar -------------------------------------------------------
_KEYWORDS = {"and", "or", "not"}


def _tokenize(expr):
    return re.findall(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*", expr)


def referenced_selections(condition):
    """Selection names a condition points at (for the validator). Keywords and
    the 'all/any of them' shortcuts reference everything, so return empty."""
    low = condition.strip().lower()
    if low in ("all of them", "any of them"):
        return set()
    return {t for t in _tokenize(condition) if t.lower() not in _KEYWORDS}


def _eval_expr(tokens, results):
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def eat():
        nonlocal pos
        t = tokens[pos]
        pos += 1
        return t

    def parse_or():
        v = parse_and()
        while peek() == "or":
            eat()
            v = parse_and() or v  # evaluate RHS (no short-circuit skips) then OR
        return v

    def parse_and():
        v = parse_not()
        while peek() == "and":
            eat()
            v = parse_not() and v
        return v

    def parse_not():
        if peek() == "not":
            eat()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        t = peek()
        if t == "(":
            eat()
            v = parse_or()
            if peek() != ")":
                raise ValueError("unbalanced parentheses in condition")
            eat()
            return v
        if t is None or t == ")" or t in _KEYWORDS:
            raise ValueError("invalid condition near %r" % t)
        eat()
        if t not in results:
            raise ValueError("condition references unknown selection %r" % t)
        return bool(results[t])

    value = parse_or()
    if pos != len(tokens):
        raise ValueError("trailing tokens in condition")
    return value


def evaluate_condition(condition, results):
    """Combine per-selection booleans per the condition string."""
    low = condition.strip().lower()
    if low == "all of them":
        return bool(results) and all(results.values())
    if low == "any of them":
        return any(results.values())
    return _eval_expr(_tokenize(condition), results)


def match(rule, event):
    """Top-level: does ``event`` (a dict) trigger ``rule``? Returns a bool."""
    detection = rule["detection"]
    results = {
        name: match_selection(event, sel)
        for name, sel in detection.items()
        if name != "condition"
    }
    return evaluate_condition(detection["condition"], results)


if __name__ == "__main__":  # tiny self-check (ponytail: keeps the core honest)
    r = {"detection": {"sel": {"event_id": 4625}, "f": {"user|re": r"\$$"},
                       "condition": "sel and not f"}}
    assert match(r, {"event_id": 4625, "user": "jsmith"}) is True
    assert match(r, {"event_id": 4625, "user": "HOST$"}) is False
    assert match(r, {"event_id": 4624, "user": "jsmith"}) is False
    print("matcher self-check OK")
