"""Assemble a gatehouse session: policy, pins, events, detectors, router, transport."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import anyio

from gatehouse import paths
from gatehouse.events.emitter import Emitter, EventContext
from gatehouse.events.fingerprint import Fingerprinter, load_or_create_key
from gatehouse.events.schema import EventAction, EventType, Severity
from gatehouse.events.sinks import JsonlFileSink, Sink, StderrSink
from gatehouse.inspect.pipeline import ScanConfig
from gatehouse.inspect.self_protect import protected_variants
from gatehouse.policy.errors import PolicyErrorKind, PolicyLoadFailed
from gatehouse.policy.loader import PolicyLoad, load_policy
from gatehouse.protocol import PINNED_SPEC_VERSION
from gatehouse.proxy.agent import agent_session_id
from gatehouse.proxy.framing import DEFAULT_MAX_FRAME_BYTES
from gatehouse.proxy.integrity import PolicyWatcher
from gatehouse.proxy.router import Router, RouterConfig, Send
from gatehouse.proxy.stdio import run_stdio


@dataclass
class RunOptions:
    server_name: str
    policy_path: Path
    command: Sequence[str]
    pins_path: Path = field(default_factory=paths.default_pins_path)
    events_dir: Path | None = field(default_factory=paths.default_events_dir)
    hmac_key_path: Path = field(default_factory=paths.default_hmac_key_path)
    expect_policy_sha256: str | None = None
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
    stderr_events: bool = True
    approval_timeout: float = 120.0
    extra_sinks: list[Sink] = field(default_factory=list[Sink])


def _check_expected_hash(load: PolicyLoad, expected: str | None) -> PolicyLoad:
    if expected is None or load.policy is None:
        return load
    if (load.sha256 or "").lower() == expected.strip().lower():
        return load
    event = PolicyLoadFailed(
        time_generated=datetime.now(UTC),
        policy_path=load.path,
        policy_sha256=load.sha256,
        error_kind=PolicyErrorKind.INTEGRITY,
        message=f"policy sha256 {load.sha256} does not match --expect-policy-sha256",
    )
    return PolicyLoad(path=load.path, sha256=load.sha256, policy=None, error=event)


def build_emitter(opts: RunOptions, context: EventContext) -> Emitter:
    sinks: list[Sink] = []
    open_error: str | None = None
    if opts.events_dir is not None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in opts.server_name)[:64]
        name = f"events-{stamp}-{safe}-{context.proxy_session_id[:8]}.jsonl"
        try:
            sinks.append(JsonlFileSink(opts.events_dir / name))
        except OSError as exc:
            sys.stderr.write(f"gatehouse: cannot open event log in {opts.events_dir}: {exc}\n")
            open_error = type(exc).__name__
    if opts.stderr_events:
        sinks.append(StderrSink())
    sinks.extend(opts.extra_sinks)
    emitter = Emitter(context, sinks)
    if open_error is not None:
        emitter.report_fail_open(
            f"cannot open the JSONL event log ({open_error}); traffic continues without it",
            EventsDir=str(opts.events_dir),
        )
    return emitter


def prepare(opts: RunOptions) -> tuple[RouterConfig, Emitter]:
    load = _check_expected_hash(load_policy(opts.policy_path), opts.expect_policy_sha256)
    context = EventContext(
        agent_session_id=agent_session_id(),
        server_name=opts.server_name,
        policy_sha256=load.sha256,
    )
    emitter = build_emitter(opts, context)
    fingerprinter = Fingerprinter(load_or_create_key(opts.hmac_key_path))

    emitter.emit(
        EventType.SESSION_STARTED,
        details={
            "PinnedSpecVersion": PINNED_SPEC_VERSION,
            "Command": opts.command[0] if opts.command else None,
            "PinsPath": str(opts.pins_path),
        },
    )
    if load.error is not None:
        err = load.error
        emitter.emit(
            EventType.POLICY_LOAD_FAILED,
            severity=Severity.CRITICAL,
            action=EventAction.FAIL_CLOSED,
            reason=f"{err.error_kind.value}: {err.message}",
            details={"PolicyPath": err.policy_path, "ErrorKind": err.error_kind.value},
        )
    else:
        emitter.emit(EventType.POLICY_LOADED, details={"PolicyPath": load.path})

    protected = [opts.policy_path, opts.pins_path, opts.hmac_key_path, paths.state_dir()]
    if opts.events_dir is not None:
        protected.append(opts.events_dir)
    config = RouterConfig(
        server_name=opts.server_name,
        policy=load,
        pins_path=opts.pins_path,
        scan=ScanConfig(protected_paths=protected_variants(protected), fingerprint=fingerprinter),
        fingerprinter=fingerprinter,
        policy_watcher=PolicyWatcher(opts.policy_path, load.sha256),
        approval_timeout=opts.approval_timeout if opts.approval_timeout > 0 else None,
    )
    return config, emitter


def run(opts: RunOptions) -> int:
    config, emitter = prepare(opts)

    def make_router(to_client: Send, to_server: Send) -> Router:
        return Router(config, emitter, to_client, to_server)

    rc = 1
    try:
        rc = anyio.run(
            lambda: run_stdio(opts.command, make_router, max_frame_bytes=opts.max_frame_bytes)
        )
        return rc
    except FileNotFoundError as exc:
        emitter.emit(
            EventType.INTERNAL_ERROR,
            severity=Severity.HIGH,
            reason=f"cannot start upstream server: {exc}",
        )
        return 127
    finally:
        emitter.emit(EventType.SESSION_ENDED, details={"ReturnCode": rc})
        emitter.close()
