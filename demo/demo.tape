# Rendered on Ubuntu by .github/workflows/demo-gif.yml (VHS on Windows is unreliable).
#   vhs demo/demo.tape   ->   docs/assets/demo.gif
Output docs/assets/demo.gif

Require uv
Set Shell "bash"
Set FontSize 15
Set Width 1300
Set Height 900
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 40ms
Set WindowBar Colorful

# Warm up uv so the recording starts instantly.
Hide
Type "uv run python -c pass && clear" Enter
Sleep 8s
Show

Type "uv run python demo/run_demo.py --pause" Sleep 700ms Enter
Sleep 2s
# 1. pin the clean server
Enter Sleep 4s
# 2. normal use
Enter Sleep 4s
# 3. rug pull: gatehouse diff shows the poisoned description
Enter Sleep 7s
# 4. next session: tool hidden, call blocked
Enter Sleep 5s
# 5. what the SOC sees
Enter Sleep 7s
