"""Message router: where every inspection and enforcement decision is made.

The router is transport-agnostic. It receives raw frames from each side and two async
callbacks to send frames to the client and to the upstream server, so the security logic
is unit-testable without processes.

Rules of thumb implemented here:

- Forward the original bytes unless gatehouse deliberately changed the message.
- Anything gatehouse cannot understand in a security-relevant position is dropped or
  blocked (fail closed) and reported.
- Responses are attributed via pending-request maps (responses carry no method).
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gatehouse.events.emitter import Emitter
from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.events.schema import Direction, EventAction, EventType, Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.pinning import PinStatus, check_pin
from gatehouse.inspect.pipeline import (
    ScanConfig,
    scan_arguments,
    scan_tool_definition,
    scan_tool_result,
)
from gatehouse.inspect.risk import classify
from gatehouse.jsonutil import as_list, as_obj, as_str
from gatehouse.policy.engine import decide, pinning_mode
from gatehouse.policy.loader import PolicyLoad
from gatehouse.policy.models import Action, FindingAction, PinningMode
from gatehouse.protocol import (
    CANCELLED,
    DISCOVER,
    INITIALIZE,
    INITIALIZED,
    INVALID_PARAMS,
    INVALID_REQUEST,
    JSONRPC_VERSION,
    METHOD_NOT_FOUND,
    SUPPORTED_VERSIONS,
    TOOLS_CALL,
    TOOLS_LIST,
    TOOLS_LIST_CHANGED,
    UNSUPPORTED_PROTOCOL_VERSION,
    UPSTREAM_UNAVAILABLE,
)
from gatehouse.proxy.framing import BatchFrame, Frame, FrameError, FrameKind, encode, parse_frame
from gatehouse.proxy.integrity import PolicyWatcher
from gatehouse.proxy.session import Pending, Session, ToolInfo
from gatehouse.state.pinstore import PinStore, PinStoreError, load_pins, pin_tools

Send = Callable[[bytes], Awaitable[None]]

_ACTION_ORDER = {Action.ALLOW: 0, Action.REQUIRE_APPROVAL: 1, Action.BLOCK: 2}
_FINDING_TO_ACTION = {
    FindingAction.LOG: Action.ALLOW,
    FindingAction.REQUIRE_APPROVAL: Action.REQUIRE_APPROVAL,
    FindingAction.BLOCK: Action.BLOCK,
}
_C2S, _S2C = Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT


def strictest(actions: Iterable[Action]) -> Action:
    return max(actions, key=lambda a: _ACTION_ORDER[a], default=Action.ALLOW)


Approver = Callable[["ApprovalRequest"], Awaitable[bool]]


@dataclass(frozen=True)
class ApprovalRequest:
    server: str
    tool: str
    reason: str
    arg_keys: tuple[str, ...]


@dataclass
class RouterConfig:
    server_name: str
    policy: PolicyLoad
    pins_path: Path
    scan: ScanConfig = field(default_factory=ScanConfig)
    fingerprinter: Fingerprinter | None = None
    policy_watcher: PolicyWatcher | None = None
    approver: Approver | None = None  # M2: elicitation-based approval


@dataclass
class _CallVerdict:
    action: Action
    reasons: list[str]
    basis: str
    policy_rule: str | None
    findings: list[Finding]


class Router:
    def __init__(
        self,
        config: RouterConfig,
        emitter: Emitter,
        send_to_client: Send,
        send_to_server: Send,
    ) -> None:
        self.cfg = config
        self.emit = emitter
        self.to_client = send_to_client
        self.to_server = send_to_server
        self.session = Session()

    # ------------------------------------------------------------------ helpers

    def _finding_action(self, finding: Finding) -> FindingAction:
        """Policy mapping severity -> action; with no valid policy, every finding blocks."""
        policy = self.cfg.policy.policy
        if policy is None:
            return FindingAction.BLOCK
        return policy.findings.for_severity(finding.severity.value)

    @property
    def _policy_mode(self) -> PinningMode:
        policy = self.cfg.policy.policy
        if policy is None:
            return PinningMode.STRICT
        return pinning_mode(policy, self.cfg.server_name)

    async def _reply_error(
        self, request_id: object, code: int, message: str, data: Any = None
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        await self.to_client(encode({"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}))

    async def _reply_blocked_tool(self, request_id: object, reason: str) -> None:
        text = f"[gatehouse] Tool call blocked: {reason}"
        await self.to_client(
            encode(
                {
                    "jsonrpc": JSONRPC_VERSION,
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": text}], "isError": True},
                }
            )
        )

    def _frame_error_event(self, direction: Direction, exc: FrameError) -> None:
        self.emit.emit(
            EventType.PROTOCOL_INVALID_FRAME,
            severity=Severity.MEDIUM,
            action=EventAction.BLOCKED,
            direction=direction,
            reason=exc.message,
            details={"Kind": exc.kind},
        )

    # ------------------------------------------------------------------ client -> server

    async def handle_client_line(self, line: bytes) -> None:
        try:
            frame = parse_frame(line)
        except BatchFrame as batch:
            self.emit.emit(
                EventType.PROTOCOL_BATCH_REJECTED,
                severity=Severity.MEDIUM,
                action=EventAction.BLOCKED,
                direction=_C2S,
                reason="JSON-RPC batches are not supported by gatehouse",
                details={"BatchSize": batch.size},
            )
            await self._reply_error(
                None, INVALID_REQUEST, "gatehouse: JSON-RPC batches are not supported"
            )
            return
        except FrameError as exc:
            self._frame_error_event(_C2S, exc)
            if exc.request_id is not None:
                await self._reply_error(
                    exc.request_id, INVALID_REQUEST, f"gatehouse: {exc.message}"
                )
            return

        if frame.kind is FrameKind.REQUEST:
            await self._client_request(frame)
        elif frame.kind is FrameKind.NOTIFICATION:
            if frame.method == INITIALIZED:
                self.session.initialized = True
            elif frame.method == CANCELLED:
                pass  # harmless if it refers to a request gatehouse already answered
            await self.to_server(frame.raw + b"\n")
        else:
            await self._client_response(frame)

    async def _client_request(self, frame: Frame) -> None:
        assert frame.id_key is not None and frame.method is not None
        params = as_obj(frame.obj.get("params")) or {}

        if frame.method == DISCOVER:
            # Steer modern-era clients to the initialize handshake gatehouse inspects.
            self.emit.emit(
                EventType.PROTOCOL_DISCOVER_DOWNGRADED,
                direction=_C2S,
                method=frame.method,
                request_id=frame.id_key,
                reason="server/discover answered by gatehouse; client falls back to initialize",
            )
            await self._reply_error(frame.id, METHOD_NOT_FOUND, "Method not found", DISCOVER)
            return

        if self.session.version_rejected and frame.method != INITIALIZE:
            await self._reply_error(
                frame.id, UNSUPPORTED_PROTOCOL_VERSION, "gatehouse: unsupported protocol version"
            )
            return

        if frame.method == INITIALIZE:
            self.session.client_capabilities = as_obj(params.get("capabilities")) or {}
            self.session.requested_version = as_str(params.get("protocolVersion"))
            info = as_obj(params.get("clientInfo")) or {}
            self.emit.context.client_name = as_str(info.get("name"))
            self.emit.context.client_version = as_str(info.get("version"))

        if frame.method == TOOLS_CALL:
            await self._tool_call(frame, params)
            return

        self.session.client_pending[frame.id_key] = Pending(
            method=frame.method,
            request_id=frame.id_key,
            has_cursor=frame.method == TOOLS_LIST and params.get("cursor") is not None,
        )
        await self.to_server(frame.raw + b"\n")

    async def _client_response(self, frame: Frame) -> None:
        key = frame.id_key
        pending = self.session.server_pending.pop(key, None) if key is not None else None
        if pending is None:
            self.emit.emit(
                EventType.PROTOCOL_UNSOLICITED_RESPONSE,
                severity=Severity.LOW,
                action=EventAction.BLOCKED,
                direction=_C2S,
                request_id=key,
                reason="response to a request the server never sent (dropped)",
            )
            return
        await self.to_server(frame.raw + b"\n")

    # ------------------------------------------------------------------ tools/call

    def _check_policy_integrity(self) -> None:
        watcher = self.cfg.policy_watcher
        if watcher is None or watcher.reported:
            return
        changed, current = watcher.changed()
        if changed:
            watcher.reported = True
            self.emit.emit(
                EventType.POLICY_TAMPERED,
                severity=Severity.HIGH,
                action=EventAction.NONE,
                reason="policy file changed on disk during the session; "
                "the original policy stays in force",
                details={"CurrentSha256": current, "Path": str(watcher.path)},
            )

    def _availability(self, tool: str) -> tuple[Action, str | None, str | None]:
        """Is this tool one the client was allowed to see? (action, reason, basis)"""
        if self._policy_mode is PinningMode.OFF:
            return Action.ALLOW, None, None
        tools = self.session.tools
        if tools is None:
            return (
                Action.BLOCK,
                "no tools/list result has been inspected in this session",
                "unlisted_tool",
            )
        if self.session.tools_stale:
            return (
                Action.BLOCK,
                "server changed its tool list; the client must list tools again",
                "stale_tool_list",
            )
        if tool not in tools:
            return (
                Action.BLOCK,
                "tool is not available (unknown, unpinned or filtered)",
                "unlisted_tool",
            )
        return Action.ALLOW, None, None

    def _verdict(self, tool: str, arguments: dict[str, Any]) -> _CallVerdict:
        server = self.cfg.server_name
        reasons: list[str] = []
        actions: list[Action] = []

        avail, avail_reason, avail_basis = self._availability(tool)
        if avail is not Action.ALLOW:
            actions.append(avail)
            reasons.append(avail_reason or "tool not available")

        decision = decide(self.cfg.policy, server, tool)
        actions.append(decision.action)
        if decision.action is not Action.ALLOW:
            reasons.append(f"policy: {decision.reason}")
        policy_rule = (
            ", ".join(f"{r.server_pattern}/{r.tool_pattern}" for r in decision.matched_rules)
            or None
        )

        info = self.session.tools.get(tool) if self.session.tools else None
        if info is not None and info.requires_approval:
            actions.append(Action.REQUIRE_APPROVAL)
            reasons.append(info.approval_reason or "tool definition flagged at listing time")

        findings = scan_arguments(server, tool, arguments, self.cfg.scan)
        for f in findings:
            act = _FINDING_TO_ACTION[self._finding_action(f)]
            actions.append(act)
            if act is not Action.ALLOW:
                reasons.append(f"detector {f.detector_id}/{f.rule_id} at {f.location}")

        final = strictest(actions)
        if avail is not Action.ALLOW:
            basis = avail_basis or "unlisted_tool"
        elif _ACTION_ORDER[final] > _ACTION_ORDER[decision.action]:
            basis = "detection"
        else:
            basis = decision.basis.value
        return _CallVerdict(final, reasons, basis, policy_rule, findings)

    async def _tool_call(self, frame: Frame, params: dict[str, Any]) -> None:
        assert frame.id_key is not None
        name = as_str(params.get("name"))
        args = as_obj(params.get("arguments", {}))
        if name is None or args is None:
            self.emit.emit(
                EventType.PROTOCOL_INVALID_FRAME,
                severity=Severity.MEDIUM,
                action=EventAction.BLOCKED,
                direction=_C2S,
                method=TOOLS_CALL,
                request_id=frame.id_key,
                reason="tools/call needs a string 'name' and object 'arguments'",
            )
            await self._reply_error(
                frame.id, INVALID_PARAMS, "gatehouse: invalid tools/call params"
            )
            return
        self._check_policy_integrity()

        info = self.session.tools.get(name) if self.session.tools else None
        risk = info.risk if info else classify(name)
        verdict = self._verdict(name, args)
        args_bytes = len(json.dumps(args, ensure_ascii=False).encode("utf-8"))
        fp = self.cfg.fingerprinter
        common: dict[str, Any] = {
            "direction": _C2S,
            "method": TOOLS_CALL,
            "request_id": frame.id_key,
            "tool_name": name,
            "tool_risk": risk,
        }

        action = verdict.action
        approved: bool | None = None
        if action is Action.REQUIRE_APPROVAL:
            approved = await self._request_approval(name, args, verdict, common)
            action = Action.ALLOW if approved else Action.BLOCK

        outcome = {
            Action.ALLOW: EventAction.APPROVED if approved else EventAction.ALLOWED,
            Action.BLOCK: EventAction.DENIED if approved is False else EventAction.BLOCKED,
        }[action]
        if (
            action is Action.BLOCK
            and approved is None
            and verdict.action is Action.REQUIRE_APPROVAL
        ):
            outcome = EventAction.APPROVAL_REQUIRED

        for f in verdict.findings:
            fa = self._finding_action(f)
            self.emit.emit_finding(f, action=outcome, details={"FindingAction": fa.value}, **common)

        reason = "; ".join(verdict.reasons) if verdict.reasons else None
        self.emit.emit(
            EventType.TOOL_CALL,
            severity=Severity.MEDIUM if action is Action.BLOCK else Severity.INFORMATIONAL,
            action=outcome,
            reason=reason,
            decision_basis=verdict.basis,
            policy_rule=verdict.policy_rule,
            arg_keys=sorted(args.keys())[:64],
            args_hmac=fp.json(args) if fp else None,
            args_bytes=args_bytes,
            details={"FindingCount": len(verdict.findings)},
            **common,
        )

        if action is Action.ALLOW:
            self.session.client_pending[frame.id_key] = Pending(
                method=TOOLS_CALL,
                request_id=frame.id_key,
                tool_name=name,
                tool_risk=risk,
                args_bytes=args_bytes,
            )
            await self.to_server(frame.raw + b"\n")
        else:
            await self._reply_blocked_tool(frame.id, reason or "blocked by gatehouse policy")

    async def _request_approval(
        self, tool: str, args: dict[str, Any], verdict: _CallVerdict, common: dict[str, Any]
    ) -> bool | None:
        """None: approval impossible (no approver / client can't elicit) -> blocked."""
        approver = self.cfg.approver
        if approver is None or not self.session.client_supports_elicitation():
            return None
        reason = "; ".join(verdict.reasons) or "policy requires approval"
        self.emit.emit(
            EventType.APPROVAL_REQUESTED,
            severity=Severity.LOW,
            action=EventAction.APPROVAL_REQUIRED,
            reason=reason,
            **common,
        )
        try:
            ok = await approver(
                ApprovalRequest(self.cfg.server_name, tool, reason, tuple(sorted(args))[:32])
            )
        except Exception as exc:  # timeouts, client errors: fail closed
            ok = False
            reason = f"{reason}; approval failed: {type(exc).__name__}"
        self.emit.emit(
            EventType.APPROVAL_GRANTED if ok else EventType.APPROVAL_DENIED,
            severity=Severity.LOW if ok else Severity.MEDIUM,
            action=EventAction.APPROVED if ok else EventAction.DENIED,
            reason=reason,
            **common,
        )
        return ok

    # ------------------------------------------------------------------ server -> client

    async def handle_server_line(self, line: bytes) -> None:
        try:
            frame = parse_frame(line)
        except BatchFrame as batch:
            self.emit.emit(
                EventType.PROTOCOL_BATCH_REJECTED,
                severity=Severity.MEDIUM,
                action=EventAction.BLOCKED,
                direction=_S2C,
                reason="JSON-RPC batch from server dropped",
                details={"BatchSize": batch.size},
            )
            return
        except FrameError as exc:
            self._frame_error_event(_S2C, exc)
            return

        if frame.kind is FrameKind.RESPONSE:
            await self._server_response(frame)
        elif frame.kind is FrameKind.REQUEST:
            assert frame.id_key is not None and frame.method is not None
            self.session.server_pending[frame.id_key] = Pending(frame.method, frame.id_key)
            self.emit.emit(
                EventType.SERVER_REQUEST,
                severity=Severity.LOW,
                direction=_S2C,
                method=frame.method,
                request_id=frame.id_key,
            )
            await self.to_client(frame.raw + b"\n")
        else:
            if frame.method == TOOLS_LIST_CHANGED:
                self.session.tools_stale = True
                self.emit.emit(EventType.TOOLS_LIST_CHANGED, severity=Severity.LOW, direction=_S2C)
            await self.to_client(frame.raw + b"\n")

    async def _server_response(self, frame: Frame) -> None:
        key = frame.id_key
        pending = self.session.client_pending.pop(key, None) if key is not None else None
        if pending is None:
            self.emit.emit(
                EventType.PROTOCOL_UNSOLICITED_RESPONSE,
                severity=Severity.MEDIUM,
                action=EventAction.BLOCKED,
                direction=_S2C,
                request_id=key,
                reason="response to a request gatehouse never forwarded (dropped)",
            )
            return
        result = as_obj(frame.obj.get("result"))
        if pending.method == INITIALIZE and result is not None:
            await self._initialize_result(frame, result)
        elif pending.method == TOOLS_LIST and result is not None:
            await self._tools_list_result(frame, result, pending)
        elif pending.method == TOOLS_CALL:
            await self._tool_result(frame, pending)
        else:
            await self.to_client(frame.raw + b"\n")

    async def _initialize_result(self, frame: Frame, result: dict[str, Any]) -> None:
        version = as_str(result.get("protocolVersion"))
        info = as_obj(result.get("serverInfo")) or {}
        self.emit.context.upstream_name = as_str(info.get("name"))
        self.emit.context.upstream_version = as_str(info.get("version"))
        if version is None or version not in SUPPORTED_VERSIONS:
            self.session.version_rejected = True
            self.emit.emit(
                EventType.PROTOCOL_UNSUPPORTED_VERSION,
                severity=Severity.HIGH,
                action=EventAction.BLOCKED,
                direction=_S2C,
                method=INITIALIZE,
                reason=f"negotiated protocol version {version!r} is not supported by gatehouse",
                details={"Supported": list(SUPPORTED_VERSIONS)},
            )
            await self._reply_error(
                frame.id,
                UNSUPPORTED_PROTOCOL_VERSION,
                "gatehouse: unsupported protocol version",
                {"supported": list(SUPPORTED_VERSIONS), "requested": version},
            )
            return
        self.session.negotiated_version = version
        self.emit.context.protocol_version = version
        self.emit.emit(EventType.PROTOCOL_NEGOTIATED, direction=_S2C, method=INITIALIZE)
        await self.to_client(frame.raw + b"\n")

    # ------------------------------------------------------------------ tools/list

    def _load_pins(self) -> PinStore | None:
        try:
            return load_pins(self.cfg.pins_path)
        except PinStoreError as exc:
            self.emit.emit(
                EventType.PIN_STORE_ERROR,
                severity=Severity.HIGH,
                action=EventAction.FAIL_CLOSED,
                reason=str(exc),
            )
            return None

    async def _tools_list_result(
        self, frame: Frame, result: dict[str, Any], pending: Pending
    ) -> None:
        mode = self._policy_mode
        server = self.cfg.server_name
        raw_tools = as_list(result.get("tools"))
        offered: list[Any] = raw_tools if raw_tools is not None else []
        if raw_tools is None:
            self.emit.emit(
                EventType.PROTOCOL_INVALID_FRAME,
                severity=Severity.MEDIUM,
                action=EventAction.FILTERED,
                direction=_S2C,
                method=TOOLS_LIST,
                reason="tools/list result has no 'tools' array",
            )

        store = self._load_pins() if mode is not PinningMode.OFF else PinStore()
        pins = store.server(server).tools if store is not None else {}

        if mode is PinningMode.TOFU and store is not None:
            if self.session.tofu_window is None:
                self.session.tofu_window = not pins
            elif not pending.has_cursor:
                self.session.tofu_window = False
        tofu_open = bool(self.session.tofu_window)

        defs = [d for d in (as_obj(t) for t in offered) if d is not None]
        names = [n for n in (as_str(d.get("name")) for d in defs) if n is not None]
        duplicates = {n for n in names if names.count(n) > 1}

        kept: list[dict[str, Any]] = []
        visible: dict[str, ToolInfo] = {}
        filtered: list[str] = []
        to_pin: dict[str, dict[str, Any]] = {}
        listing_ctx: dict[str, Any] = {"direction": _S2C, "method": TOOLS_LIST}

        for tool in offered:
            tdef = as_obj(tool)
            name = as_str(tdef.get("name")) if tdef is not None else None
            if tdef is None or name is None:
                filtered.append("<invalid>")
                continue
            risk = classify(name, as_obj(tdef.get("annotations")))
            ctx: dict[str, Any] = {**listing_ctx, "tool_name": name, "tool_risk": risk}

            if name in duplicates:
                self.emit.emit_finding(
                    Finding(
                        detector_id="listing.duplicate_name",
                        rule_id="duplicate-tool-name",
                        severity=Severity.HIGH,
                        summary="the server offered two tools with the same name",
                        location=f"tools[{name}]",
                        mitre=("AML.T0010.005",),
                        owasp=("LLM03",),
                    ),
                    action=EventAction.FILTERED,
                    **ctx,
                )
                filtered.append(name)
                continue

            if store is None:  # pin store unreadable: fail closed
                filtered.append(name)
                continue

            pin = pins.get(name)
            check = check_pin(tdef, pin.sha256 if pin else None, pin.definition if pin else None)
            if mode is not PinningMode.OFF and check.status is PinStatus.CHANGED:
                self.emit.emit_finding(
                    Finding(
                        detector_id="listing.pin_mismatch",
                        rule_id="tool-definition-changed",
                        severity=Severity.HIGH,
                        summary="tool definition changed since it was pinned ("
                        + (", ".join(check.changed_fields) or "unknown fields")
                        + ")",
                        location=f"tools[{name}]",
                        mitre=("AML.T0010.005", "T1195"),
                        owasp=("LLM03",),
                    ),
                    action=EventAction.FILTERED,
                    details={
                        "PinnedSha256": check.pinned_digest,
                        "CurrentSha256": check.digest,
                        "ChangedFields": list(check.changed_fields),
                    },
                    **ctx,
                )
                filtered.append(name)
                continue
            untrusted_new = check.status is PinStatus.UNPINNED and (
                mode is PinningMode.STRICT or (mode is PinningMode.TOFU and not tofu_open)
            )
            if untrusted_new:
                strict = mode is PinningMode.STRICT
                self.emit.emit_finding(
                    Finding(
                        detector_id="listing.unpinned",
                        rule_id="tool-not-pinned" if strict else "new-tool-on-pinned-server",
                        severity=Severity.MEDIUM,
                        summary=(
                            "tool is not pinned (strict mode); run `gatehouse pin` to approve it"
                            if strict
                            else "new tool appeared after this server was first trusted; "
                            "run `gatehouse pin --tool NAME` to approve it"
                        ),
                        location=f"tools[{name}]",
                        mitre=("AML.T0010.005",),
                        owasp=("LLM03",),
                    ),
                    action=EventAction.FILTERED,
                    details={"CurrentSha256": check.digest},
                    **ctx,
                )
                filtered.append(name)
                continue

            # content detectors on the definition (M2)
            findings = scan_tool_definition(tdef, defs, self.cfg.scan)
            worst = strictest(_FINDING_TO_ACTION[self._finding_action(f)] for f in findings)
            outcome = {
                Action.BLOCK: EventAction.FILTERED,
                Action.REQUIRE_APPROVAL: EventAction.APPROVAL_REQUIRED,
                Action.ALLOW: EventAction.LOGGED,
            }[worst]
            for f in findings:
                self.emit.emit_finding(f, action=outcome, **ctx)
            if worst is Action.BLOCK:
                filtered.append(name)
                continue

            if mode is PinningMode.TOFU and check.status is PinStatus.UNPINNED and tofu_open:
                to_pin[name] = tdef
            kept.append(tdef)
            visible[name] = ToolInfo(
                name=name,
                digest=check.digest,
                risk=risk,
                definition=tdef,
                requires_approval=worst is Action.REQUIRE_APPROVAL,
                approval_reason=(
                    "tool definition flagged: "
                    + ", ".join(f"{f.detector_id}/{f.rule_id}" for f in findings)
                    if worst is Action.REQUIRE_APPROVAL
                    else None
                ),
            )

        if to_pin:
            try:
                pin_tools(self.cfg.pins_path, server, to_pin, pinned_by="tofu", only_new=True)
                for name in to_pin:
                    self.emit.emit(
                        EventType.PIN_CREATED,
                        severity=Severity.LOW,
                        action=EventAction.NONE,
                        reason="trust on first use",
                        details={"Sha256": visible[name].digest, "PinnedBy": "tofu"},
                        tool_name=name,
                        **listing_ctx,
                    )
            except (PinStoreError, OSError) as exc:
                # Couldn't persist TOFU pins: the tools stay visible for this session but
                # will be treated as new next time. Report loudly.
                self.emit.emit(
                    EventType.PIN_STORE_ERROR,
                    severity=Severity.HIGH,
                    reason=f"could not save TOFU pins: {exc}",
                )

        if pending.has_cursor and self.session.tools is not None:
            self.session.tools.update(visible)
        else:
            self.session.tools = visible
        self.session.tools_stale = False

        self.emit.emit(
            EventType.TOOLS_LISTED,
            severity=Severity.LOW if filtered else Severity.INFORMATIONAL,
            action=EventAction.FILTERED if filtered else EventAction.ALLOWED,
            direction=_S2C,
            method=TOOLS_LIST,
            request_id=pending.request_id,
            details={
                "Offered": len(offered),
                "Visible": len(kept),
                "Filtered": filtered[:64],
                "PinningMode": mode.value,
            },
        )

        if filtered or raw_tools is None:
            new_obj = dict(frame.obj)
            new_result = dict(result)
            new_result["tools"] = kept
            new_obj["result"] = new_result
            await self.to_client(encode(new_obj))
        else:
            await self.to_client(frame.raw + b"\n")

    # ------------------------------------------------------------------ tools/call result

    async def _tool_result(self, frame: Frame, pending: Pending) -> None:
        latency = (time.monotonic() - pending.started) * 1000.0
        result = as_obj(frame.obj.get("result"))
        is_error = result is not None and result.get("isError") is True
        findings: list[Finding] = []
        if result is not None:
            findings = scan_tool_result(
                self.cfg.server_name, pending.tool_name or "", result, self.cfg.scan
            )
        worst = strictest(_FINDING_TO_ACTION[self._finding_action(f)] for f in findings)
        # Approval is not possible after the fact: a flagged result is withheld.
        blocked = worst is not Action.ALLOW
        outcome = (
            EventAction.BLOCKED
            if blocked
            else (EventAction.LOGGED if findings else EventAction.ALLOWED)
        )
        common: dict[str, Any] = {
            "direction": _S2C,
            "method": TOOLS_CALL,
            "request_id": pending.request_id,
            "tool_name": pending.tool_name,
            "tool_risk": pending.tool_risk,
        }
        for f in findings:
            self.emit.emit_finding(f, action=outcome, **common)
        self.emit.emit(
            EventType.TOOL_RESULT,
            severity=Severity.MEDIUM if blocked else Severity.INFORMATIONAL,
            action=outcome,
            latency_ms=round(latency, 3),
            result_bytes=len(frame.raw),
            args_bytes=pending.args_bytes,
            details={
                "IsError": is_error,
                "HasError": "error" in frame.obj,
                "FindingCount": len(findings),
            },
            **common,
        )
        if blocked:
            detectors = ", ".join(sorted({f"{f.detector_id}/{f.rule_id}" for f in findings}))
            await self._reply_blocked_tool(frame.id, f"tool result withheld ({detectors})")
        else:
            await self.to_client(frame.raw + b"\n")

    # ------------------------------------------------------------------ lifecycle

    async def upstream_exited(self, returncode: int | None) -> None:
        self.emit.emit(
            EventType.UPSTREAM_EXITED,
            severity=Severity.LOW,
            details={"ReturnCode": returncode, "PendingRequests": len(self.session.client_pending)},
        )
        for key, pending in list(self.session.client_pending.items()):
            del self.session.client_pending[key]
            await self._reply_error(
                json.loads(key),
                UPSTREAM_UNAVAILABLE,
                f"gatehouse: upstream server exited ({pending.method})",
            )
