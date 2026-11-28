"""Model-written mutations for held-out v2 (D-046): paraphrase and translation.

    python -m attacks.heldout2.llm --model qwen2.5:7b --out attacks/heldout2/llm.json

Runs against a local Ollama server (``OLLAMA_HOST``, default http://127.0.0.1:11434) with
temperature 0 and a fixed seed. It is run once, in the ``heldout2-llm`` workflow, and its
output is committed and frozen; ``mutate.py`` only reads the file. Rewrites that drop
the seed's marker (the attacker's goal) are discarded by ``mutate.py``, and this script
records how many there were.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from attacks.heldout2.mutate import Seed, load_seeds

TASKS = {
    "paraphrase": (
        "Rewrite the text below in different words. Keep its meaning, its tone and any "
        "request it makes exactly the same."
    ),
    "translate-de": "Translate the text below into German.",
    "translate-es": "Translate the text below into Spanish.",
}


def _prompt(task: str, seed: Seed) -> str:
    keep = f' Copy this exact string unchanged: "{seed.marker}".' if seed.marker else ""
    return (
        f"{TASKS[task]}{keep} Output only the rewritten text, with no preamble, quotes "
        f"or notes.\n\nText:\n{seed.text}"
    )


def _generate(host: str, model: str, prompt: str) -> str:
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "seed": 7, "num_predict": 400},
        }
    ).encode()
    url = f"{host}/api/generate"
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"OLLAMA_HOST must be an http(s) URL, not {host!r}")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=600) as resp:  # noqa: S310 (scheme checked)
        data = cast(dict[str, Any], json.loads(resp.read()))
    return str(data.get("response", "")).strip()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m attacks.heldout2.llm")
    p.add_argument("--model", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--meta", type=Path, help="where to write the run metadata (JSON)")
    args = p.parse_args(argv)
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    if not host.startswith("http"):
        host = "http://" + host
    out: dict[str, dict[str, str]] = {}
    kept = dropped = 0
    for seed in load_seeds():
        if seed.kind == "argument":
            continue  # arguments are data, not prose
        for task in TASKS:
            text = _generate(host, args.model, _prompt(task, seed))
            if not text:
                continue
            out.setdefault(seed.id, {})[task] = text
            if seed.marker is None or seed.marker in text:
                kept += 1
            else:
                dropped += 1
            sys.stderr.write(f"{seed.id} {task}: {len(text)} chars\n")
    args.out.write_text(
        json.dumps(out, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    meta = {
        "model": args.model,
        "options": {"temperature": 0, "seed": 7},
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "rewrites": kept + dropped,
        "kept_marker": kept,
        "dropped_marker": dropped,
    }
    if args.meta:
        args.meta.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    sys.stderr.write(json.dumps(meta) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
