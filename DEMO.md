# 60-second demo script

Record a terminal with a clear, large font. Each step is a single command;
pause ~2s on the output before moving on.

**0:00 — The pitch (say it)**
"Detection as code: SIEM rules as versioned YAML that you lint, unit-test, and gate in CI."

**0:05 — Show a rule (1 file)**
```bash
sed -n '1,25p' detection_as_code/rules/suspicious_powershell.yml
```
Point out: `detection` operators, the `condition`, the `mitre` mapping, and the bundled `tests`.

**0:20 — The offline test gate**
```bash
pytest -q
```
Show: `39 passed`. Say "no network, no API key — pure deterministic core."

**0:30 — The pipeline / CI gate**
```bash
python -m detection_as_code pipeline
```
Show: `5 rules | 0 lint errors | 14/14 tests passed | 5 tactics, 5 techniques covered` and `gate: PASS`.

**0:40 — Catch a regression**
```bash
python -m detection_as_code scan
```
Show the 5 ALERT lines firing on the bundled sample events, each tagged with its MITRE technique.

**0:50 — AI helper (optional, needs local Ollama)**
```bash
python -m detection_as_code draft "powershell downloading from a pastebin url"
```
Point at the "AI-GENERATED DRAFT — advisory only, a human MUST review" banner. Say: "the AI only drafts; the engine never trusts it."

**0:58 — Close**
"Rules reviewed in pull requests, tested on every commit, mapped to ATT&CK. That's detection as code."

---
Tip: if no local LLM is running, `draft` prints a clean "LLM unavailable" message and exits — safe to show, or skip that step.
