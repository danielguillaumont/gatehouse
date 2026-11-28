"""External corpora for evaluation v2 (M6, D-047): MCPTox and agent-egress-bench.

    python -m attacks.external prepare --out .cache/external
    python -m attacks run --scenarios .cache/external/mcptox --out reports/mcptox
    python -m attacks run --scenarios .cache/external/egress --out reports/egress

``prepare`` downloads each corpus at a pinned commit, checks the bytes against pinned
SHA-256 digests, and converts the MCP cases into suite scenarios (milestone
``external``: measured, never gated, never tuned on). Nothing from either corpus is
committed to this repository:

- **MCPTox** (zhiqiangwang4/MCPTox-Benchmark): benchmark data CC BY 4.0 "to the extent
  the MCPTox contributors hold the rights"; the authentic tool definitions come from
  third-party MCP servers. Wang et al., "MCPTox: A Benchmark for Tool Poisoning on
  Real-World MCP Servers", AAAI 2026, doi:10.1609/aaai.v40i42.40895. Changes: each
  poisoned tool becomes one listing scenario next to its server's authentic tools; each
  authentic tool becomes one benign listing scenario.
- **agent-egress-bench** (pipelab-org/agent-egress-bench, v1.2.0, Apache-2.0). Only the
  ``mcp_stdio`` cases are converted; ``SOURCES.json`` lists what was skipped and why.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any, cast

MILESTONE = "external"

MCPTOX = {
    "name": "MCPTox",
    "repo": "https://github.com/zhiqiangwang4/MCPTox-Benchmark",
    "commit": "630121b3275f74cc72d000a7a056e4d3c68648ef",
    "commit_date": "2026-11-15",
    "license": "CC-BY-4.0 (benchmark data, to the extent the contributors hold the rights)",
    "files": {
        "pure_tool.json": "54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617",
        "response_all.json": "79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03",
    },
}
EGRESS = {
    "name": "agent-egress-bench",
    "repo": "https://github.com/pipelab-org/agent-egress-bench",
    "tag": "v1.2.0",
    "commit": "451a5db634a5d7b9c2e965307f3f16bd79747fed",
    "license": "Apache-2.0",
    # SHA-256 over the sorted "path sha256" lines of every cases/**/*.json file, so the
    # digest doesn't depend on how GitHub packs the archive.
    "cases_digest": "39f3f719b28ac9b67cd40cf449d6d25173288622bf42d9c73e16d06ce3614cce",
}

_POISON_TAGS = {"owasp": ["LLM01", "LLM03"], "atlas": ["AML.T0110", "AML.T0051.001"]}


def _get(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(url)
    with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310 (https only)
        return cast(bytes, resp.read())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _needle(text: str, where: object) -> str | None:
    """A 24-character slice from the middle of ``text`` that appears in ``_dump(where)``
    (JSON escapes quotes, backslashes and control characters, so pick a plain run)."""
    runs = [r for r in re.split(r'["\\\x00-\x1f]', text) if len(r) >= 8]
    if not runs:
        return None
    run = max(runs, key=len)
    mid = len(run) // 2
    needle = run[max(0, mid - 12) : mid + 12]
    return needle if needle in _dump(where) else None


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in cast(dict[str, object], value).values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in cast(list[object], value) for s in _strings(v)]
    return []


def _schema_for(arguments: dict[str, Any]) -> dict[str, Any]:
    kinds: dict[type, str] = {
        str: "string",
        bool: "boolean",
        int: "integer",
        float: "number",
        list: "array",
    }
    props = {k: {"type": kinds.get(type(cast(object, v)), "object")} for k, v in arguments.items()}
    return {"type": "object", "properties": props}


# ---------------------------------------------------------------- MCPTox


def _authentic_tools(prompt: str) -> list[dict[str, Any]]:
    """Parse the 'Tool: / Description: / Arguments:' blocks of a clean system prompt."""
    tools: list[dict[str, Any]] = []
    for chunk in prompt.split("\nTool: ")[1:]:
        name = chunk.split("\n", 1)[0].strip()
        m = re.search(r"\nDescription: (.*?)\nArguments:\n", chunk, re.S)
        if not name or m is None:
            continue
        props: dict[str, Any] = {}
        required: list[str] = []
        rest = chunk[m.end() :]
        for line in rest.split("\n"):
            am = re.match(r"- ([^:\s]+): (.*)$", line)
            if am is None:
                break
            desc = am.group(2)
            if desc.endswith("(required)"):
                required.append(am.group(1))
                desc = desc[: -len("(required)")].strip()
            prop: dict[str, Any] = {"type": "string"}
            if desc and desc != "No description":
                prop["description"] = desc
            props[am.group(1)] = prop
        schema: dict[str, Any] = {"type": "object", "properties": props}
        if required:
            schema["required"] = required
        tools.append({"name": name, "description": m.group(1).strip(), "inputSchema": schema})
    return tools


def convert_mcptox(pure: Any, responses: Any) -> tuple[list[dict[str, Any]], list[str]]:
    servers: dict[str, list[dict[str, Any]]] = {}
    for s in cast(dict[str, dict[str, Any]], responses["servers"]).values():
        servers[str(s["server_name"])] = _authentic_tools(str(s["clean_system_promot"]))
    out: list[dict[str, Any]] = []
    skipped: list[str] = []
    for server, tools in sorted(servers.items()):
        for t in tools:
            sid = f"benign.mcptox.{_slug(server)}.{_slug(t['name'])}"
            out.append(
                {
                    "id": sid,
                    "category": "benign",
                    "expect": "benign",
                    "milestone": MILESTONE,
                    "title": f"MCPTox authentic tool: {server}/{t['name']}",
                    "server": {"tools": [t]},
                    "steps": ["list"],
                }
            )
    for group in cast(list[dict[str, dict[str, Any]]], pure):
        for key, case in sorted(group.items()):
            server = str(case["server_name"])
            description = str(case["tool_content"]).strip()
            poisoned: dict[str, Any] = {
                "name": str(case["tool_name"]),
                "description": description,
                "inputSchema": {"type": "object", "properties": {}},
            }
            needle = _needle(description, poisoned)
            if needle is None:
                skipped.append(f"mcptox {key}: no usable success marker")
                continue
            peers = [t for t in servers.get(server, []) if t["name"] != poisoned["name"]]
            out.append(
                {
                    "id": f"mcptox.{_slug(key)}",
                    "category": "tool_poisoning",
                    "milestone": MILESTONE,
                    "title": f"MCPTox {key}: {case.get('security risk', '')}".strip(),
                    **_POISON_TAGS,
                    "server": {"tools": [*peers, poisoned]},
                    "steps": ["list"],
                    "success_if": {
                        "client_saw_tool": {"tool": poisoned["name"], "contains": needle}
                    },
                    "source": f"MCPTox {key} ({case.get('paradigm', '')})",
                }
            )
    return out, skipped


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-").lower() or "x"


# ---------------------------------------------------------------- agent-egress-bench


def _messages(case: dict[str, Any]) -> list[dict[str, Any]]:
    payload = cast(dict[str, Any], case.get("payload") or {})
    return cast(list[dict[str, Any]], payload.get("jsonrpc_messages") or [])


def convert_egress_case(case: dict[str, Any]) -> dict[str, Any] | str:
    """One scenario, or the reason the case was skipped."""
    cid = str(case["id"])
    kind = str(case["input_type"])
    verdict = str(case["expected_verdict"])
    if case.get("transport") != "mcp_stdio":
        return f"transport {case.get('transport')}"
    if verdict not in ("block", "allow"):
        return f"verdict {verdict}"
    if "budget_limit_calls" in cast(dict[str, Any], case["payload"]):
        return "call-budget case (no equivalent policy in the eval setup)"
    msgs = _messages(case)
    benign = verdict == "allow"
    sc: dict[str, Any] = {
        "id": f"{'benign.' if benign else ''}egress.{cid}",
        "category": "benign" if benign else f"egress_{case['category']}",
        "milestone": MILESTONE,
        "title": f"agent-egress-bench {cid}: {case.get('title', '')}",
        "source": f"agent-egress-bench v1.2.0 {cid} ({case.get('why_expected', '')})",
    }
    if benign:
        sc["expect"] = "benign"
    calls = [m for m in msgs if m.get("method") == "tools/call"]
    listings = [
        cast(list[dict[str, Any]], cast(dict[str, Any], m["result"])["tools"])
        for m in msgs
        if isinstance(m.get("result"), dict) and "tools" in cast(dict[str, Any], m["result"])
    ]
    replies = {
        m.get("id"): m["result"]
        for m in msgs
        if isinstance(m.get("result"), dict) and "tools" not in cast(dict[str, Any], m["result"])
    }
    if kind == "mcp_tool_definition" and listings:
        phases = [{"server": {"tools": tools}, "steps": ["list"]} for tools in listings]
        last = listings[-1]
        target = max(last, key=lambda t: len(_dump(t)))
        if len(phases) == 1:
            sc.update(phases[0])
        else:
            sc["phases"] = phases
        if not benign:
            if not isinstance(target.get("name"), str):
                return "tool without a name (no client_saw_tool condition can name it)"
            needle = _needle(max(_strings(target), key=len), target)
            if needle is None:
                return "no usable success marker"
            sc["success_if"] = {
                "client_saw_tool": {"tool": str(target["name"]), "contains": needle}
            }
        return sc
    if kind == "mcp_tool_result" and replies and not calls:
        result = cast(dict[str, Any], next(iter(replies.values())))
        tool = "fetch"
        sc["server"] = {
            "tools": [
                {
                    "name": tool,
                    "description": "Fetch a resource.",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ],
            "results": {tool: result},
        }
        sc["steps"] = ["list", {"call": {"tool": tool, "arguments": {}}}]
        if not benign:
            needle = _needle(max(_strings(result), key=len), result)
            if needle is None:
                return "no usable success marker"
            sc["success_if"] = {"client_saw_result": {"tool": tool, "contains": needle}}
        return sc
    if kind in ("mcp_tool_call", "mcp_tool_sequence") and calls:
        tools: dict[str, dict[str, Any]] = {}
        results: dict[str, Any] = {}
        steps: list[Any] = ["list"]
        for c in calls:
            params = cast(dict[str, Any], c.get("params") or {})
            name = str(params.get("name"))
            args = cast(dict[str, Any], params.get("arguments") or {})
            tools.setdefault(
                name, {"name": name, "description": f"{name}.", "inputSchema": _schema_for(args)}
            )
            if c.get("id") in replies:
                results[name] = replies[c.get("id")]
            steps.append({"call": {"tool": name, "arguments": args}})
        sc["server"] = {"tools": list(tools.values()), **({"results": results} if results else {})}
        sc["steps"] = steps
        if not benign:
            last = cast(dict[str, Any], calls[-1]["params"])
            strings = _strings(last.get("arguments") or {})
            needle = _needle(max(strings, key=len), last) if strings else None
            if needle is None:
                return "no usable success marker"
            sc["success_if"] = {"server_received": {"tool": str(last["name"]), "contains": needle}}
        return sc
    return f"input_type {kind} not supported by the stdio harness"


def _cases_digest(files: dict[str, bytes]) -> str:
    lines = "".join(f"{p} {_sha(files[p])}\n" for p in sorted(files))
    return _sha(lines.encode())


def egress_cases(archive: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            parts = member.name.split("/", 1)
            if len(parts) == 2 and parts[1].startswith("cases/") and member.name.endswith(".json"):
                f = tar.extractfile(member)
                if f is not None:
                    out[parts[1]] = f.read()
    return out


def convert_egress(files: dict[str, bytes]) -> tuple[list[dict[str, Any]], list[str]]:
    out: list[dict[str, Any]] = []
    skipped: list[str] = []
    for path in sorted(files):
        case = cast(dict[str, Any], json.loads(files[path]))
        if not str(case.get("category", "")).startswith("mcp") and not (
            case.get("category") == "false_positive" and case.get("transport") == "mcp_stdio"
        ):
            continue
        res = convert_egress_case(case)
        if isinstance(res, str):
            skipped.append(f"{case['id']}: {res}")
        else:
            out.append(res)
    return out, skipped


# ---------------------------------------------------------------- CLI


def _write(path: Path, scenarios: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(scenarios, ensure_ascii=True, indent=1) + "\n", encoding="utf-8")


def prepare(out: Path) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    raw: dict[str, Any] = {}
    files = cast(dict[str, str], MCPTOX["files"])
    for name, digest in files.items():
        data = _get(
            f"https://raw.githubusercontent.com/zhiqiangwang4/MCPTox-Benchmark/{MCPTOX['commit']}/{name}"
        )
        if _sha(data) != digest:
            raise SystemExit(f"MCPTox {name}: sha256 {_sha(data)} != pinned {digest}")
        raw[name] = json.loads(data)
    scenarios, skipped = convert_mcptox(raw["pure_tool.json"], raw["response_all.json"])
    _write(out / "mcptox" / "mcptox.yaml", scenarios)
    meta["mcptox"] = {**MCPTOX, **_counts(scenarios), "skipped": skipped}

    archive = _get(
        f"https://codeload.github.com/pipelab-org/agent-egress-bench/tar.gz/{EGRESS['commit']}"
    )
    cases = egress_cases(archive)
    digest = _cases_digest(cases)
    if EGRESS["cases_digest"] and digest != EGRESS["cases_digest"]:
        raise SystemExit(f"agent-egress-bench: cases digest {digest} != pinned")
    scenarios, skipped = convert_egress(cases)
    _write(out / "egress" / "egress.yaml", scenarios)
    meta["egress"] = {**EGRESS, "cases_digest": digest, **_counts(scenarios), "skipped": skipped}
    (out / "SOURCES.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return meta


def _counts(scenarios: list[dict[str, Any]]) -> dict[str, int]:
    benign = sum(1 for s in scenarios if s.get("expect") == "benign")
    return {"attacks": len(scenarios) - benign, "benign": benign}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m attacks.external")
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("prepare", help="download, verify and convert the external corpora")
    pr.add_argument("--out", type=Path, default=Path(".cache/external"))
    args = p.parse_args(argv)
    meta = prepare(args.out)
    for name, m in meta.items():
        sys.stderr.write(
            f"{name}: {m['attacks']} attacks, {m['benign']} benign, {len(m['skipped'])} skipped\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
