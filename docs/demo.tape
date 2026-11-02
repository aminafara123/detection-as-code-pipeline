# Renders docs/demo.gif with charmbracelet/vhs (needs vhs, ttyd and ffmpeg on PATH).
# Run from the repo root, with the deps installed in .venv:  vhs docs/demo.tape
# Follows DEMO.md: a YAML rule -> offline tests -> CI pipeline gate -> scan bundled events (optional LLM draft step skipped).
Output docs/demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set TypingSpeed 40ms

Hide
Type "VIRTUAL_ENV_DISABLE_PROMPT=1 source .venv/bin/activate"
Enter
Wait@120s
Type "clear"
Enter
Wait@120s
Show
Sleep 500ms

Type "sed -n '1,25p' detection_as_code/rules/suspicious_powershell.yml"
Sleep 400ms
Enter
Wait@120s
Sleep 4s

Hide
Type "clear"
Enter
Sleep 200ms
Show
Type "pytest -q"
Sleep 400ms
Enter
Wait@120s
Sleep 2s

Type "python -m detection_as_code pipeline"
Sleep 400ms
Enter
Wait@120s
Sleep 3s

Type "python -m detection_as_code scan"
Sleep 400ms
Enter
Wait@120s
Sleep 4s

Sleep 1s
