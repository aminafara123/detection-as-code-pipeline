"""Thin LLM client: one function, OpenAI-compatible chat endpoint, env-configured.

Defaults target the user's local Ollama. No API key is hardcoded. If the
endpoint is unreachable or returns garbage, ``complete()`` raises LLMError and
callers degrade gracefully. Stdlib only, so importing this never pulls a
network dependency and the deterministic core stays offline.

Env:
  LLM_BASE_URL  default http://127.0.0.1:11434/v1
  LLM_MODEL     default qwen3:30b-a3b-instruct-2507-q4_K_M
  LLM_API_KEY   default ollama   (Ollama ignores it; a hosted provider uses it)
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

BASE_URL = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434/v1")
MODEL = os.environ.get("LLM_MODEL", "qwen3:30b-a3b-instruct-2507-q4_K_M")
API_KEY = os.environ.get("LLM_API_KEY", "ollama")


class LLMError(RuntimeError):
    """Raised when the LLM endpoint is unreachable or returns an unusable reply."""


def complete(prompt, system=None, temperature=0.2, timeout=120):
    """Send one chat completion and return the assistant text. Raises LLMError."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = json.dumps(
        {"model": MODEL, "messages": messages,
         "temperature": temperature, "stream": False}
    ).encode()
    req = urllib.request.Request(
        BASE_URL.rstrip("/") + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer %s" % API_KEY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise LLMError("LLM endpoint unreachable at %s: %s" % (BASE_URL, exc)) from exc
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError("Unexpected LLM response shape: %r" % (data,)) from exc
