"""LLM drafter: offline. The AI path is mocked; the deterministic core is not
touched here. Confirms AI output is clearly labelled and failures degrade."""
import urllib.error

import pytest

from detection_as_code import __main__ as cli
from detection_as_code import llm


def test_draft_rule_is_labelled_ai_generated(monkeypatch):
    monkeypatch.setattr(llm, "complete", lambda *a, **k: "id: x\ntitle: Y\n")
    out = cli.draft_rule("detect something")
    assert "AI-GENERATED DRAFT" in out
    assert "human MUST review" in out
    assert "id: x" in out


def test_complete_raises_llmerror_when_unreachable(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr(llm.urllib.request, "urlopen", boom)
    with pytest.raises(llm.LLMError):
        llm.complete("hi")


def test_cmd_draft_exits_cleanly_when_llm_down(monkeypatch, capsys):
    def boom(*a, **k):
        raise llm.LLMError("down")
    monkeypatch.setattr(llm, "complete", boom)
    rc = cli.cmd_draft(type("A", (), {"description": "x"})())
    assert rc == 2  # graceful non-crash exit code
