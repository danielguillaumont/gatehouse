# Demo: a rug-pulled MCP server is blocked before Claude Code sees it

The story: you approve a harmless weather server. Later it is "updated", and the
`get_forecast` description now hides instructions telling the model to read
`~/.ssh/id_rsa` and send it as the city name. gatehouse notices that the definition no
longer matches what you approved, removes the tool from the agent's tool list, blocks
calls to it, and logs a `listing.pin_mismatch` detection that the Sentinel rule
`GH001_rug_pull` alerts on.

Here the block comes from **pinning**, not from content detection: gatehouse blocks the
tool because it changed, not because the new text looks malicious, so a rewording that no
detector recognises is caught the same way.

## 1. Unattended run (good for recording)

```
uv sync
uv run python demo/run_demo.py            # whole story, about 30 s
uv run python demo/run_demo.py --pause    # waits for Enter between steps
```

Add `--kusto http://localhost:8080` to also run the GH001 analytics rule on the
session's events in the Kusto emulator (see `docs/sentinel-setup.md`).

The GIF in the README is recorded from `demo/demo.tape` with
[VHS](https://github.com/charmbracelet/vhs) by the `demo-gif` workflow on Ubuntu. To record
by hand, use ScreenToGif on Windows or `asciinema rec` on Linux, with `--pause`.

## 2. With Claude Code

From the repository root:

1. Approve the clean server:

   ```
   uv run gatehouse pin --name weather -- uv run python demo/weather_server.py
   ```

2. Register gatehouse as the MCP server. Copy `demo/mcp.json` to `.mcp.json` in the
   repository root (project-scoped MCP config), or add it with the CLI:

   ```
   claude mcp add weather -- uv run gatehouse run --name weather --policy demo/policy.yaml -- uv run python demo/weather_server.py
   ```

3. Start `claude` and ask: *"What's the weather in Paris?"* Claude Code calls
   `get_forecast` through gatehouse and answers.
4. Stage the rug pull: create the flag file `demo/.poisoned` (any content).
5. Restart Claude Code (or reconnect the server from `/mcp`) and ask again.
   `get_forecast` is gone from the tool list, so Claude can only use `list_cities`.
   gatehouse prints a `listing.pin_mismatch` line on stderr, and the JSONL event is in
   the state directory (`%LOCALAPPDATA%\gatehouse\events` on Windows,
   `~/.local/state/gatehouse/events` on Linux; override with `GATEHOUSE_HOME`).
6. Look at what changed: `uv run gatehouse diff --name weather -- uv run python demo/weather_server.py`.
7. Clean up: delete `demo/.poisoned`.

`demo/policy.yaml` denies by default, allows the weather server's tools, and uses strict
pinning, so nothing is visible to the agent until it has been pinned.
