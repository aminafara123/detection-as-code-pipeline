"""Matcher core: every operator and every condition combinator, match + non-match."""
import pytest

from detection_as_code.matcher import (evaluate_condition, match,
                                        match_selection, parse_key,
                                        referenced_selections)


# --- operators ---------------------------------------------------------------
def test_equals_case_insensitive():
    assert match_selection({"a": "Powershell"}, {"a": "powershell"}) is True
    assert match_selection({"a": "cmd"}, {"a": "powershell"}) is False


def test_equals_numeric_coerced():
    assert match_selection({"id": 4625}, {"id": 4625}) is True
    assert match_selection({"id": 4625}, {"id": "4625"}) is True
    assert match_selection({"id": 4624}, {"id": 4625}) is False


def test_contains():
    assert match_selection({"cmd": "x -enc y"}, {"cmd|contains": "-enc"}) is True
    assert match_selection({"cmd": "x y"}, {"cmd|contains": "-enc"}) is False


def test_startswith():
    assert match_selection({"p": "C:\\Win"}, {"p|startswith": "c:\\win"}) is True
    assert match_selection({"p": "D:\\Win"}, {"p|startswith": "c:\\win"}) is False


def test_regex():
    assert match_selection({"u": "HOST$"}, {"u|re": r"\$$"}) is True
    assert match_selection({"u": "jsmith"}, {"u|re": r"\$$"}) is False


def test_in_list():
    assert match_selection({"id": 4732}, {"id|in": [4728, 4732]}) is True
    assert match_selection({"id": 4624}, {"id|in": [4728, 4732]}) is False


def test_list_value_is_or():
    sel = {"cmd|contains": ["-enc", "IEX"]}
    assert match_selection({"cmd": "run IEX(...)"}, sel) is True
    assert match_selection({"cmd": "run nothing"}, sel) is False


def test_missing_field_never_matches():
    assert match_selection({"other": 1}, {"a|contains": "x"}) is False
    assert match_selection({"other": 1}, {"a": "x"}) is False


def test_all_fields_in_selection_are_anded():
    sel = {"id": 4625, "type|contains": "net"}
    assert match_selection({"id": 4625, "type": "network"}, sel) is True
    assert match_selection({"id": 4625, "type": "local"}, sel) is False


def test_parse_key_unknown_operator_raises():
    with pytest.raises(ValueError):
        parse_key("field|bogus")


# --- condition combinators ---------------------------------------------------
def test_all_of_them():
    assert evaluate_condition("all of them", {"a": True, "b": True}) is True
    assert evaluate_condition("all of them", {"a": True, "b": False}) is False
    assert evaluate_condition("all of them", {}) is False


def test_any_of_them():
    assert evaluate_condition("any of them", {"a": False, "b": True}) is True
    assert evaluate_condition("any of them", {"a": False, "b": False}) is False


def test_and_or_not():
    r = {"a": True, "b": False}
    assert evaluate_condition("a and b", r) is False
    assert evaluate_condition("a or b", r) is True
    assert evaluate_condition("a and not b", r) is True
    assert evaluate_condition("not a", r) is False


def test_parentheses_and_precedence():
    r = {"a": True, "b": False, "c": True}
    assert evaluate_condition("a and (b or c)", r) is True
    assert evaluate_condition("(a and b) or c", r) is True
    assert evaluate_condition("a and b or c", r) is True  # and binds tighter


def test_condition_unknown_name_raises():
    with pytest.raises(ValueError):
        evaluate_condition("a and z", {"a": True})


def test_referenced_selections():
    assert referenced_selections("sel and not filt") == {"sel", "filt"}
    assert referenced_selections("all of them") == set()


# --- end-to-end match() ------------------------------------------------------
def test_match_with_filter():
    rule = {"detection": {
        "sel": {"event_id": 4625},
        "filt": {"user|re": r"\$$"},
        "condition": "sel and not filt"}}
    assert match(rule, {"event_id": 4625, "user": "jsmith"}) is True
    assert match(rule, {"event_id": 4625, "user": "HOST$"}) is False
    assert match(rule, {"event_id": 4624, "user": "jsmith"}) is False
