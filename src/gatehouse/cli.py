"""gatehouse command line.

    gatehouse run --name NAME --policy FILE [options] -- <server command...>
    gatehouse pin --name NAME [--pins FILE] -- <server command...>
    gatehouse diff --name NAME [--pins FILE] -- <server command...>
    gatehouse validate-policy FILE
    gatehouse policy-hash FILE
    gatehouse table-schema

Only ``run`` speaks MCP on stdout; the other commands print human output.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from gatehouse import __version__, paths
from gatehouse.events.sentinel import DEFAULT_STREAM, SentinelConfig
from gatehouse.proxy.framing import DEFAULT_MAX_FRAME_BYTES


def _out(text: str) -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _split_command(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    args = list(argv)
    if "--" in args:
        i = args.index("--")
        return args[:i], args[i + 1 :]
    return args, []


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gatehouse", description="Security gateway for MCP.")
    p.add_argument("--version", action="version", version=f"gatehouse {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="proxy one stdio MCP server (put the server command after --)")
    run.add_argument("--name", required=True, help="server name used in policy and events")
    run.add_argument("--policy", required=True, type=Path)
    run.add_argument("--pins", type=Path, default=None, help="pin store (default: state dir)")
    run.add_argument("--events-dir", type=Path, default=None, help="JSONL event directory")
    run.add_argument("--no-event-log", action="store_true", help="do not write JSONL events")
    run.add_argument("--quiet", action="store_true", help="no human-readable events on stderr")
    run.add_argument("--expect-policy-sha256", default=None)
    run.add_argument("--max-frame-bytes", type=int, default=DEFAULT_MAX_FRAME_BYTES)
    run.add_argument(
        "--approval-timeout",
        type=float,
        default=120.0,
        help="seconds to wait for the user to approve a require_approval call through "
        "MCP elicitation (0 disables approval prompts: such calls are blocked)",
    )
    run.add_argument(
        "--sentinel-endpoint",
        default=None,
        help="Logs Ingestion endpoint (DCE) to send events to Microsoft Sentinel; "
        "default: $GATEHOUSE_SENTINEL_ENDPOINT. Needs gatehouse[sentinel].",
    )
    run.add_argument(
        "--sentinel-dcr-id",
        default=None,
        help="immutable id of the data collection rule; default: $GATEHOUSE_SENTINEL_DCR_ID",
    )
    run.add_argument(
        "--sentinel-stream",
        default=None,
        help="DCR stream name; default: $GATEHOUSE_SENTINEL_STREAM or Custom-GatehouseEvents_CL",
    )

    for name, helptext in (
        ("pin", "approve (pin) the current tool definitions of a server"),
        ("diff", "compare a server's current tools with its pins (exit 1 on drift)"),
    ):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--name", required=True)
        sp.add_argument("--pins", type=Path, default=None)
        sp.add_argument("--timeout", type=float, default=60.0)
        if name == "pin":
            sp.add_argument("--tool", action="append", default=None, help="only pin these tools")

    vp = sub.add_parser("validate-policy", help="validate a policy file")
    vp.add_argument("policy", type=Path)
    ph = sub.add_parser("policy-hash", help="print the SHA-256 used by --expect-policy-sha256")
    ph.add_argument("policy", type=Path)
    sub.add_parser("table-schema", help="print the GatehouseEvents_CL column schema (JSON)")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    own, command = _split_command(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(own)

    if args.cmd == "run":
        return _cmd_run(args, command)
    if args.cmd in ("pin", "diff"):
        if not command:
            _err(f"gatehouse {args.cmd}: give the server command after --")
            return 2
        return _cmd_pin(args, command) if args.cmd == "pin" else _cmd_diff(args, command)
    if args.cmd == "validate-policy":
        return _cmd_validate(args.policy)
    if args.cmd == "policy-hash":
        from gatehouse.policy.loader import load_policy

        load = load_policy(args.policy)
        if load.sha256 is None:
            _err(f"cannot hash {args.policy}")
            return 1
        _out(load.sha256)
        return 0 if load.ok else 1
    if args.cmd == "table-schema":
        from gatehouse.events.schema import sentinel_columns

        _out(json.dumps(sentinel_columns(), indent=2))
        return 0
    return 2


def _cmd_run(args: argparse.Namespace, command: list[str]) -> int:
    if not command:
        _err("gatehouse run: give the server command after --")
        return 2
    from gatehouse.proxy.app import RunOptions, run

    try:
        sentinel = _sentinel_config(args)
    except ValueError as exc:
        _err(f"gatehouse: {exc}")
        return 2
    opts = RunOptions(
        server_name=args.name,
        policy_path=args.policy,
        command=command,
        pins_path=args.pins or paths.default_pins_path(),
        events_dir=None if args.no_event_log else (args.events_dir or paths.default_events_dir()),
        expect_policy_sha256=args.expect_policy_sha256,
        max_frame_bytes=args.max_frame_bytes,
        stderr_events=not args.quiet,
        approval_timeout=args.approval_timeout,
        sentinel=sentinel,
    )
    return run(opts)


def _sentinel_config(args: argparse.Namespace) -> SentinelConfig | None:
    env = SentinelConfig.from_env()
    endpoint = args.sentinel_endpoint or (env.endpoint if env else None)
    rule_id = args.sentinel_dcr_id or (env.rule_id if env else None)
    if not endpoint and not rule_id:
        return None
    if not endpoint or not rule_id:
        # Asked for Sentinel but can't deliver: refuse to start rather than run silently
        # without the SOC feed.
        raise ValueError(
            "Sentinel needs both an endpoint and a DCR id "
            "(--sentinel-endpoint/--sentinel-dcr-id or the GATEHOUSE_SENTINEL_* variables)"
        )
    stream = args.sentinel_stream or (env.stream if env else None) or DEFAULT_STREAM
    return SentinelConfig(endpoint, rule_id, stream)


def _cmd_validate(path: Path) -> int:
    from gatehouse.policy.loader import load_policy

    load = load_policy(path)
    if load.policy is None:
        assert load.error is not None
        _err(f"INVALID ({load.error.error_kind.value}): {load.error.message}")
        return 1
    policy = load.policy
    _out(f"OK  {path}  sha256={load.sha256}")
    _out(
        f"    default_action={policy.default_action.value}  "
        f"pinning={policy.pinning.value}  rules={len(policy.rules)}"
    )
    return 0


def _list_tools(command: list[str], timeout: float) -> list[dict[str, object]]:
    from gatehouse.client import StdioClient

    with StdioClient(command, timeout=timeout) as client:
        client.initialize(client_name="gatehouse-pin")
        return client.list_tools()


def _cmd_pin(args: argparse.Namespace, command: list[str]) -> int:
    from gatehouse.state.pinstore import pin_tools

    pins_path: Path = args.pins or paths.default_pins_path()
    tools = _list_tools(command, args.timeout)
    by_name = {str(t["name"]): t for t in tools if isinstance(t.get("name"), str)}
    if args.tool:
        missing = [t for t in args.tool if t not in by_name]
        if missing:
            _err(f"not offered by the server: {', '.join(missing)}")
            return 1
        by_name = {k: v for k, v in by_name.items() if k in args.tool}
    store = pin_tools(pins_path, args.name, by_name, pinned_by="pin", replace_server=not args.tool)
    for name, pin in sorted(store.server(args.name).tools.items()):
        if name in by_name:
            _out(f"pinned  {args.name}/{name}  {pin.sha256[:16]}")
    _out(f"{len(by_name)} tool(s) pinned in {pins_path}")
    return 0


def _cmd_diff(args: argparse.Namespace, command: list[str]) -> int:
    from gatehouse.inspect.pinning import PinStatus, check_pin, render_diff
    from gatehouse.state.pinstore import load_pins

    pins_path: Path = args.pins or paths.default_pins_path()
    pins = load_pins(pins_path).server(args.name).tools
    tools = _list_tools(command, args.timeout)
    drift = 0
    seen: set[str] = set()
    for tool in tools:
        name = str(tool.get("name"))
        seen.add(name)
        pin = pins.get(name)
        check = check_pin(tool, pin.sha256 if pin else None, pin.definition if pin else None)
        if check.status is PinStatus.MATCH:
            _out(f"  ok       {name}")
        elif check.status is PinStatus.UNPINNED:
            drift += 1
            _out(f"+ new      {name}  {check.digest[:16]}")
        else:
            drift += 1
            _out(f"~ changed  {name}  fields: {', '.join(check.changed_fields)}")
            assert pin is not None
            _out(render_diff(pin.definition, tool, name))
    for name in sorted(set(pins) - seen):
        drift += 1
        _out(f"- removed  {name}")
    _out(f"{drift} difference(s)")
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
