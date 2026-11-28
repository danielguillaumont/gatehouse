"""Message router: where every inspection and enforcement decision is made.

The router is transport-agnostic. It receives raw frames from each side and two async
callbacks to send frames to the client and to the upstream server, so the security logic
is unit-testable without processes. One router is one *channel*: a stdio process, or one
Streamable HTTP request. Channels that talk to the same upstream share a ``Session``.

Rules of thumb implemented here:

- Forward the original bytes unless gatehouse deliberately changed the message.
- Anything gatehouse cannot understand in a security-relevant position is dropped or
  blocked (fail closed) and reported.
- Responses are attributed via pending-request maps (responses carry no method).
- Both protocol eras are inspected (D-036): the legacy ``initialize`` handshake and the
  modern per-request ``_meta`` envelope of 2026-07-28. A connection is one or the other.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Awaitable, Callable, Coroutine, Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import anyio
from anyio.abc import TaskGroup

from gatehouse.canonical import canonical_sha256
from gatehouse.classify.base import (
    HIT_RULE,
    UNAVAILABLE_RULE,
    Verdict,
    definition_text,
    findings_for,
    is_enforcing,
)
from gatehouse.classify.runner import ClassifierRunner
from gatehouse.events.emitter import Emitter
from gatehouse.events.fingerprint import Fingerprinter
from gatehouse.events.schema import Direction, EventAction, EventType, Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.pinning import PinStatus, check_pin, tool_digest
from gatehouse.inspect.pipeline import (
    ScanConfig,
    scan_arguments,
    scan_tool_definition,
    scan_tool_result,
)
from gatehouse.inspect.protocol import (
    HEADER_ID,
    detect_downgrade,
    detect_instruction_injection,
    x_mcp_headers,
)
from gatehouse.inspect.provenance import argument_fingerprints, is_copy, result_fingerprints
from gatehouse.inspect.risk import classify
from gatehouse.inspect.secrets import detect_secrets
from gatehouse.inspect.server_requests import SHAPE_ID, inspect_server_request
from gatehouse.inspect.walk import WalkStats
from gatehouse.jsonutil import as_list, as_obj, as_str
from gatehouse.policy.conditions import all_hold, parse_conditions
from gatehouse.policy.engine import decide, pinning_mode
from gatehouse.policy.labels import tool_labels
from gatehouse.policy.loader import PolicyLoad
from gatehouse.policy.models import (
    Action,
    ClassifierMode,
    ClassifierSurface,
    ControlSettings,
    FindingAction,
    FlowMode,
    Label,
    PinningMode,
    ProtocolSettings,
    SamplingMode,
)
from gatehouse.protocol import (
    ALL_VERSIONS,
    CACHEABLE_METHODS,
    CANCELLED,
    DISCOVER,
    ELICITATION_CREATE,
    INITIALIZE,
    INITIALIZED,
    INPUT_REQUEST_CAPABILITY,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    JSONRPC_VERSION,
    LEGACY_VERSIONS,
    META_SERVER_INFO,
    META_SUBSCRIPTION_ID,
    METHOD_NOT_FOUND,
    MODERN_VERSIONS,
    MRTR_METHODS,
    PROMPTS_GET,
    RESOURCES_READ,
    RESULT_COMPLETE,
    RESULT_INPUT_REQUIRED,
    SAMPLING_CREATE,
    SUBSCRIPTIONS_ACKNOWLEDGED,
    SUBSCRIPTIONS_LISTEN,
    TOOLS_CALL,
    TOOLS_LIST,
    TOOLS_LIST_CHANGED,
    UNSUPPORTED_PROTOCOL_VERSION,
    UPSTREAM_UNAVAILABLE,
)
from gatehouse.proxy.approval import ApprovalRequest, Elicitor, elicitation_params, is_approval
from gatehouse.proxy.framing import BatchFrame, Frame, FrameError, FrameKind, encode, parse_frame
from gatehouse.proxy.integrity import PolicyWatcher
from gatehouse.proxy.modern import (
    APPROVAL_KEY,
    RequestMeta,
    StateSigner,
    approval_input_required,
    call_binding,
    internal_meta,
    is_gatehouse_state,
    request_meta,
)
from gatehouse.proxy.session import Era, Grant, Pending, Session, ToolInfo
from gatehouse.state.control import (
    MAX_QUARANTINE_BYTES,
    ControlStore,
    ControlStoreError,
    KillState,
)
from gatehouse.state.flow import FlowStore, FlowStoreError
from gatehouse.state.pinstore import (
    PinStore,
    PinStoreError,
    load_pins,
    pin_protocol,
    pin_tools,
)

Send = Callable[[bytes], Awaitable[None]]

_ACTION_ORDER = {Action.ALLOW: 0, Action.REQUIRE_APPROVAL: 1, Action.BLOCK: 2}
_FINDING_TO_ACTION = {
    FindingAction.LOG: Action.ALLOW,
    FindingAction.REQUIRE_APPROVAL: Action.REQUIRE_APPROVAL,
    FindingAction.BLOCK: Action.BLOCK,
}
_C2S, _S2C = Direction.CLIENT_TO_SERVER, Direction.SERVER_TO_CLIENT
# Which listen-filter field opts a client into each change notification.
_LISTEN_FILTER = {
    TOOLS_LIST_CHANGED: "toolsListChanged",
    "notifications/prompts/list_changed": "promptsListChanged",
    "notifications/resources/list_changed": "resourcesListChanged",
    "notifications/resources/updated": "resourceSubscriptions",
}
INTERNAL_ID_PREFIX = "gatehouse-internal-"
INTERNAL_TIMEOUT_S = 15.0
MAX_LIST_PAGES = 50
GRANT_TTL_S = 600.0
GRANT_USES = 8


def strictest(actions: Iterable[Action]) -> Action:
    return max(actions, key=lambda a: _ACTION_ORDER[a], default=Action.ALLOW)


Approver = Callable[[ApprovalRequest], Awaitable[bool]]


@dataclass
class RouterConfig:
    server_name: str
    policy: PolicyLoad
    pins_path: Path
    scan: ScanConfig = field(default_factory=ScanConfig)
    fingerprinter: Fingerprinter | None = None
    policy_watcher: PolicyWatcher | None = None
    # Approval of require_approval calls. With ``approval_timeout`` set and no explicit
    # ``approver``, the router asks the user through MCP elicitation (proxy/approval.py).
    approver: Approver | None = None
    approval_timeout: float | None = None
    # Signs gatehouse's MRTR approval requestState (modern era). None: no MRTR approval.
    state_signer: StateSigner | None = None
    # True behind the Streamable HTTP transport: x-mcp-header annotations are enforced.
    http: bool = False
    # Session flow control (D-040, D-042): labels shared by every gatehouse under one
    # agent, keyed by AgentSessionId. Only touched when the policy turns flow.mode on.
    flow: FlowStore = field(default_factory=lambda: FlowStore(None))
    agent_session_id: str = "local"
    # Response controls (ADR-0006, D-044): kill switch, circuit breaker, approval budget,
    # quarantine and scoped grants, shared by every gatehouse on the machine.
    control: ControlStore = field(default_factory=lambda: ControlStore(None))
    # Model-based detectors from the policy (ADR-0007, D-050).
    classifiers: tuple[ClassifierRunner, ...] = ()


@dataclass
class _FlowCheck:
    mode: FlowMode
    tool_labels: frozenset[Label]
    session_labels: frozenset[Label]
    violation: bool
    store_error: str | None = None


@dataclass
class _CallVerdict:
    action: Action
    reasons: list[str]
    basis: str
    policy_rule: str | None
    findings: list[Finding]
    flow: _FlowCheck | None = None
    # Only the policy (or the Rule of Two) asks for approval, so a scoped grant may answer.
    grantable: bool = False


@dataclass
class _Waiter:
    done: anyio.Event = field(default_factory=anyio.Event)
    frame: Frame | None = None


@dataclass
class _Call:
    """A tools/call being decided."""

    frame: Frame
    name: str
    args: dict[str, Any]
    risk: str
    common: dict[str, Any]
    args_bytes: int
    meta: RequestMeta
    raw: bytes  # what to forward (gatehouse's own MRTR fields stripped)
    approval: bool | None = None  # decided by a gatehouse approval retry
    approval_note: str | None = None
    answer_findings: list[Finding] = field(default_factory=list[Finding])
    flow_labels: frozenset[str] = frozenset()  # effective labels, when flow control is on


class Router:
    def __init__(
        self,
        config: RouterConfig,
        emitter: Emitter,
        send_to_client: Send,
        send_to_server: Send,
        session: Session | None = None,
    ) -> None:
        self.cfg = config
        self.emit = emitter
        self.to_client = send_to_client
        self.to_server = send_to_server
        self.session = session if session is not None else Session()
        # The caller's identity: an OIDC principal behind `gatehouse serve --oidc-*`
        # (ADR-0008), "local" on stdio.
        self.principal = "local"
        # requests from the client forwarded on this channel, keyed by JSON-encoded id
        self.client_pending: dict[str, Pending] = {}
        # requests gatehouse itself sent upstream (its own tools/list)
        self._internal: dict[str, _Waiter] = {}
        self.elicitor: Elicitor | None = None
        self.approver: Approver | None = config.approver
        if self.approver is None and config.approval_timeout is not None:
            self.elicitor = Elicitor(send_to_client, config.approval_timeout)
            self.approver = self.elicitor
        # Set by the transport. Calls waiting for approval (or for gatehouse's own
        # tools/list) run here so the client reader loop stays free. Without a task group
        # (unit tests) the call is awaited inline.
        self.task_group: TaskGroup | None = None
        # (classifier id, tool digest) -> verdict: listings repeat, mostly unchanged
        self._definition_verdicts: dict[tuple[str, str], Verdict] = {}
        self._kill_seen = False  # last kill-switch state this process reported
        self._local_locks: dict[str, str] = {}  # sessions locked while the store failed

    # ------------------------------------------------------------------ helpers

    def _finding_action(self, finding: Finding) -> FindingAction:
        """Policy mapping severity -> action; with no valid policy, every finding blocks."""
        policy = self.cfg.policy.policy
        if policy is None:
            return FindingAction.BLOCK
        if finding.detector_id == PROVENANCE_ID:
            # Its own setting (D-043): a copy of private data after untrusted input.
            tainted = finding.severity is Severity.HIGH
            return policy.flow.provenance if tainted else FindingAction.LOG
        return policy.findings.for_severity(finding.severity.value)

    def _worst(self, findings: Iterable[Finding]) -> Action:
        return strictest(_FINDING_TO_ACTION[self._finding_action(f)] for f in findings)

    @property
    def _policy_mode(self) -> PinningMode:
        policy = self.cfg.policy.policy
        if policy is None:
            return PinningMode.STRICT
        return pinning_mode(policy, self.cfg.server_name)

    @property
    def _protocol(self) -> ProtocolSettings:
        policy = self.cfg.policy.policy
        return policy.protocol if policy is not None else ProtocolSettings()

    def _args_fp(self, args: dict[str, Any]) -> str:
        fp = self.cfg.fingerprinter
        return fp.json(args) if fp is not None else canonical_sha256(args)

    async def _reply_error(
        self, request_id: object, code: int, message: str, data: Any = None
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        await self.to_client(encode({"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}))

    async def _reply_result(self, request_id: object, result: dict[str, Any]) -> None:
        await self.to_client(
            encode({"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result})
        )

    async def _reply_blocked_tool(
        self, request_id: object, reason: str, modern: bool = False
    ) -> None:
        await self._reply_tool_text(request_id, f"[gatehouse] Tool call blocked: {reason}", modern)

    async def _reply_tool_text(self, request_id: object, text: str, modern: bool) -> None:
        result: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": True}
        if modern:
            result = {"resultType": RESULT_COMPLETE, **result}
        await self._reply_result(request_id, result)

    async def _reply_withheld(self, frame: Frame, pending: Pending, reason: str) -> None:
        """Replace a server response gatehouse will not deliver."""
        if pending.method == TOOLS_CALL:
            await self._reply_blocked_tool(frame.id, reason, pending.modern)
        else:
            await self._reply_error(
                frame.id, INTERNAL_ERROR, f"gatehouse: response withheld: {reason}"
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

    def _note_client(self, meta: RequestMeta) -> None:
        ctx = self.emit.context
        ctx.protocol_version = meta.version
        if meta.client_info is not None:
            ctx.client_name = as_str(meta.client_info.get("name"))
            ctx.client_version = as_str(meta.client_info.get("version"))

    def _note_server(self, result: dict[str, Any]) -> None:
        info = as_obj((as_obj(result.get("_meta")) or {}).get(META_SERVER_INFO))
        if info is not None:
            self.emit.context.upstream_name = as_str(info.get("name"))
            self.emit.context.upstream_version = as_str(info.get("version"))

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

    async def _era_conflict(self, frame: Frame, why: str) -> None:
        self.emit.emit(
            EventType.PROTOCOL_ERA_CONFLICT,
            severity=Severity.MEDIUM,
            action=EventAction.BLOCKED,
            direction=_C2S,
            method=frame.method,
            request_id=frame.id_key,
            reason=why,
            details={"Era": self.session.era.value if self.session.era else None},
        )
        await self._reply_error(frame.id, INVALID_REQUEST, f"gatehouse: {why}")

    async def _unsupported_version(self, frame: Frame, requested: str | None) -> None:
        # An enveloped request is answered with the 2026-07-28 versions this connection
        # can reach, which are what server/discover advertised through gatehouse.
        # Listing handshake versions here would contradict that discover result.
        offered = [v for v in self.session.offered_versions if v in MODERN_VERSIONS]
        supported = offered or list(reversed(MODERN_VERSIONS))
        self.emit.emit(
            EventType.PROTOCOL_UNSUPPORTED_VERSION,
            severity=Severity.LOW,
            action=EventAction.BLOCKED,
            direction=_C2S,
            method=frame.method,
            request_id=frame.id_key,
            reason=f"request protocol version {requested!r} is not inspected by gatehouse",
            details={"Supported": supported},
        )
        await self._reply_error(
            frame.id,
            UNSUPPORTED_PROTOCOL_VERSION,
            "Unsupported protocol version",
            {"supported": supported, "requested": requested},
        )

    async def _client_request(self, frame: Frame) -> None:
        assert frame.id_key is not None and frame.method is not None
        params = as_obj(frame.obj.get("params")) or {}
        meta = request_meta(params)
        method = frame.method

        if method == DISCOVER:
            if meta.present and meta.version not in MODERN_VERSIONS:
                await self._unsupported_version(frame, meta.version)
                return
            if meta.present:
                self._note_client(meta)
            self.client_pending[frame.id_key] = Pending(
                DISCOVER,
                frame.id_key,
                modern=True,
                version=meta.version,
                client_caps=meta.capabilities,
            )
            await self.to_server(frame.raw + b"\n")
            return

        if method == INITIALIZE:
            if self.session.era is Era.MODERN:
                # A dual-era client may pipeline initialize with its server/discover probe
                # (Claude Code 2.1.332 does). Answer as a 2026-07-28 server does: -32022
                # naming the modern versions, which such a client takes as modern evidence.
                self.emit.emit(
                    EventType.PROTOCOL_ERA_CONFLICT,
                    severity=Severity.LOW,
                    action=EventAction.BLOCKED,
                    direction=_C2S,
                    method=INITIALIZE,
                    request_id=frame.id_key,
                    reason="initialize on a connection already serving 2026-07-28",
                    details={"Era": Era.MODERN.value},
                )
                await self._reply_error(
                    frame.id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "connection is serving the 2026-07-28 protocol; "
                    "the initialize handshake is not accepted",
                    {
                        "supported": list(MODERN_VERSIONS),
                        "requested": as_str(params.get("protocolVersion")),
                    },
                )
                return
            if self.session.downgrade_blocked:
                self.emit.emit(
                    EventType.PROTOCOL_UNSUPPORTED_VERSION,
                    severity=Severity.HIGH,
                    action=EventAction.BLOCKED,
                    direction=_C2S,
                    method=INITIALIZE,
                    request_id=frame.id_key,
                    reason="legacy handshake refused: the server was seen speaking a newer "
                    "protocol revision (downgrade)",
                )
                await self._reply_error(
                    frame.id,
                    UNSUPPORTED_PROTOCOL_VERSION,
                    "gatehouse: protocol downgrade refused",
                    {
                        "supported": list(MODERN_VERSIONS),
                        "requested": as_str(params.get("protocolVersion")),
                    },
                )
                return
            # The era latches to legacy when the handshake *succeeds* (_initialize_result):
            # a pipelined initialize that the server refuses must not lock the connection.
            self.session.client_capabilities = as_obj(params.get("capabilities")) or {}
            self.session.requested_version = as_str(params.get("protocolVersion"))
            info = as_obj(params.get("clientInfo")) or {}
            self.emit.context.client_name = as_str(info.get("name"))
            self.emit.context.client_version = as_str(info.get("version"))
        elif meta.present:
            if self.session.era is Era.LEGACY:
                await self._era_conflict(
                    frame, "2026-07-28 request on a connection that used the initialize handshake"
                )
                return
            problem = meta.problem()
            if problem is not None:
                await self._invalid_meta(frame, problem)
                return
            if meta.version not in MODERN_VERSIONS:
                await self._unsupported_version(frame, meta.version)
                return
            self.session.era = Era.MODERN
            self._note_client(meta)
        elif self.session.era is Era.MODERN:
            await self._invalid_meta(frame, meta.problem() or "missing _meta")
            return

        if self.session.version_rejected and method != INITIALIZE:
            await self._reply_error(
                frame.id, UNSUPPORTED_PROTOCOL_VERSION, "gatehouse: unsupported protocol version"
            )
            return

        if method == TOOLS_CALL:
            await self._tool_call(frame, params, meta)
            return

        if method in (PROMPTS_GET, RESOURCES_READ) and "inputResponses" in params:
            findings = self._answer_findings(params.get("inputResponses"))
            if self._worst(findings) is Action.BLOCK:
                self._emit_findings(
                    findings, EventAction.BLOCKED, _C2S, method=method, request_id=frame.id_key
                )
                await self._reply_error(
                    frame.id,
                    INVALID_PARAMS,
                    "gatehouse: blocked a secret in an answer to the server",
                )
                return
            self._emit_findings(
                findings, EventAction.LOGGED, _C2S, method=method, request_id=frame.id_key
            )

        pending = Pending(
            method=method,
            request_id=frame.id_key,
            has_cursor=method == TOOLS_LIST and params.get("cursor") is not None,
            modern=meta.present,
            version=meta.version,
            client_caps=meta.capabilities,
        )
        if method == SUBSCRIPTIONS_LISTEN:
            pending.listen_filter = as_obj(params.get("notifications")) or {}
        if method == INITIALIZE:
            pending.requested_version = as_str(params.get("protocolVersion"))
        self.client_pending[frame.id_key] = pending
        await self.to_server(frame.raw + b"\n")

    async def _invalid_meta(self, frame: Frame, problem: str) -> None:
        self.emit.emit(
            EventType.PROTOCOL_INVALID_META,
            severity=Severity.LOW,
            action=EventAction.BLOCKED,
            direction=_C2S,
            method=frame.method,
            request_id=frame.id_key,
            reason=problem,
        )
        await self._reply_error(frame.id, INVALID_PARAMS, f"gatehouse: {problem}")

    async def _client_response(self, frame: Frame) -> None:
        if self.elicitor is not None and self.elicitor.resolve(frame):
            return  # the user's answer to a gatehouse approval request: never forwarded
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
        if pending.method == ELICITATION_CREATE:
            findings = self._answer_findings(frame.obj.get("result"))
            if self._worst(findings) is Action.BLOCK:
                # The user typed a secret into a server's form: the server gets a decline.
                self._emit_findings(
                    findings, EventAction.BLOCKED, _C2S, method=ELICITATION_CREATE, request_id=key
                )
                await self.to_server(
                    encode(
                        {
                            "jsonrpc": JSONRPC_VERSION,
                            "id": frame.id,
                            "result": {"action": "decline"},
                        }
                    )
                )
                return
        await self.to_server(frame.raw + b"\n")

    def _answer_findings(self, value: object) -> list[Finding]:
        """Secrets in what the user answered a server (elicitation results)."""
        if value is None:
            return []
        found = detect_secrets(value, "inputResponses", self.cfg.scan.fingerprint, WalkStats())
        return [f.model_copy(update={"detector_id": "answers.secrets"}) for f in found]

    def _emit_findings(
        self, findings: Iterable[Finding], action: EventAction, direction: Direction, **fields: Any
    ) -> None:
        for f in findings:
            self.emit.emit_finding(f, action=action, direction=direction, **fields)

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

    def _verdict(self, tool: str, arguments: dict[str, Any], extra: list[Finding]) -> _CallVerdict:
        server = self.cfg.server_name
        reasons: list[str] = []
        actions: list[Action] = []

        kill = self._kill_switch()
        if kill is not None:
            actions.append(Action.BLOCK)
            reasons.append(f"kill switch engaged: {kill.reason}")
        lock = self._session_lock()
        if lock is not None:
            actions.append(Action.BLOCK)
            reasons.append(f"session locked: {lock}; a human can run `gatehouse unlock`")

        avail, avail_reason, avail_basis = self._availability(tool)
        if avail is not Action.ALLOW:
            actions.append(avail)
            reasons.append(avail_reason or "tool not available")

        info = self.session.tools.get(tool) if self.session.tools else None
        flow = self._flow_check(tool, info)
        decision = decide(
            self.cfg.policy,
            server,
            tool,
            arguments,
            tool_labels=flow.tool_labels if flow else frozenset(),
            session_labels=flow.session_labels if flow else frozenset(),
            principal=self.principal,
        )
        if flow is not None:
            flow.violation = decision.flow_violation
        policy_at = len(actions)
        actions.append(decision.action)
        if decision.action is not Action.ALLOW:
            reasons.append(f"policy: {decision.reason}")
        policy_rule = (
            ", ".join(f"{r.server_pattern}/{r.tool_pattern}" for r in decision.matched_rules)
            or None
        )

        if info is not None and info.requires_approval:
            actions.append(Action.REQUIRE_APPROVAL)
            reasons.append(info.approval_reason or "tool definition flagged at listing time")

        findings = scan_arguments(server, tool, arguments, self.cfg.scan) + extra
        if flow is not None:
            findings += self._provenance(tool, arguments, flow)
        for f in findings:
            act = _FINDING_TO_ACTION[self._finding_action(f)]
            actions.append(act)
            if act is not Action.ALLOW:
                reasons.append(f"detector {f.detector_id}/{f.rule_id} at {f.location}")

        final = strictest(actions)
        others = actions[:policy_at] + actions[policy_at + 1 :]
        grantable = decision.action is Action.REQUIRE_APPROVAL and (
            strictest(others) is Action.ALLOW if others else True
        )
        if kill is not None:
            basis = "kill_switch"
        elif lock is not None:
            basis = "circuit_breaker"
        elif avail is not Action.ALLOW:
            basis = avail_basis or "unlisted_tool"
        elif _ACTION_ORDER[final] > _ACTION_ORDER[decision.action]:
            basis = "detection"
        else:
            basis = decision.basis.value
        return _CallVerdict(final, reasons, basis, policy_rule, findings, flow, grantable)

    def _flow_mode(self) -> FlowMode:
        policy = self.cfg.policy.policy
        return policy.flow.mode if policy is not None else FlowMode.OFF

    def _flow_check(self, tool: str, info: ToolInfo | None) -> _FlowCheck | None:
        """Labels for the Rule-of-Two check, or None when flow control is off."""
        policy = self.cfg.policy.policy
        mode = self._flow_mode()
        if policy is None or mode is FlowMode.OFF:
            return None
        raw = info.definition.get("annotations") if info is not None else None
        annotations = as_obj(raw)
        labels = tool_labels(policy, self.cfg.server_name, tool, annotations)
        try:
            session = self.cfg.flow.labels(self.cfg.agent_session_id)
            error = None
        except FlowStoreError as exc:
            # Fail closed: a session we can't read is treated as holding every label.
            session = frozenset(Label)
            error = str(exc)
            self.emit.emit(
                EventType.INTERNAL_ERROR,
                severity=Severity.HIGH,
                action=EventAction.FAIL_CLOSED,
                tool_name=tool,
                reason=f"flow store unreadable; treating the session as holding every label: {exc}",
                details={"Component": "flow_store"},
            )
        return _FlowCheck(mode, labels, session, violation=False, store_error=error)

    # ------------------------------------------------------------- response controls

    @property
    def _controls(self) -> ControlSettings:
        policy = self.cfg.policy.policy
        return policy.controls if policy is not None else ControlSettings()

    def _control_error(self, what: str, exc: Exception, tool: str | None = None) -> None:
        self.emit.emit(
            EventType.INTERNAL_ERROR,
            severity=Severity.HIGH,
            action=EventAction.FAIL_CLOSED,
            tool_name=tool,
            reason=f"control store: {what}: {exc}",
            details={"Component": "control_store"},
        )

    def _kill_switch(self) -> KillState | None:
        """The kill switch, emitting control.kill_switch when this process sees it change."""
        state = self.cfg.control.kill_state()
        engaged = state is not None
        if engaged != self._kill_seen:
            self._kill_seen = engaged
            self.emit.emit(
                EventType.CONTROL_KILL_SWITCH,
                severity=Severity.HIGH if engaged else Severity.MEDIUM,
                action=EventAction.BLOCKED if engaged else EventAction.NONE,
                reason=state.reason if state is not None else "kill switch released",
                details={
                    "State": "engaged" if engaged else "released",
                    "Source": state.source if state is not None else "file",
                },
            )
        return state

    def _session_lock(self) -> str | None:
        session = self.cfg.agent_session_id
        if session in self._local_locks:
            return self._local_locks[session]
        try:
            return self.cfg.control.locked(session)
        except ControlStoreError as exc:
            self._control_error("unreadable; treating the session as locked", exc)
            return "the control store can't be read"

    def _maybe_strike(self, findings: Iterable[Finding], tool: str) -> None:
        """Count one circuit-breaker strike for a call or result with a high finding."""
        threshold = self._controls.circuit_breaker
        if threshold <= 0 or not any(
            f.severity in (Severity.HIGH, Severity.CRITICAL) and f.rule_id not in _NOT_STRIKES
            for f in findings
        ):
            return
        session = self.cfg.agent_session_id
        try:
            n = self.cfg.control.strike(session)
            if n < threshold:
                return
            reason = f"circuit breaker: {n} calls or results with high findings"
            self.cfg.control.lock(session, reason)
        except ControlStoreError as exc:
            self._control_error("strike not recorded; locking this process's session", exc, tool)
            n, reason = threshold, "circuit breaker (control store unavailable)"
            self._local_locks[session] = reason
        if n == threshold:
            self.emit.emit(
                EventType.CONTROL_CIRCUIT_BREAKER,
                severity=Severity.HIGH,
                action=EventAction.BLOCKED,
                tool_name=tool,
                reason=reason,
                details={"Strikes": n, "Threshold": threshold},
            )

    def _spend_budget(self, call: _Call) -> bool:
        budget = self._controls.approval_budget
        try:
            return self.cfg.control.take_prompt(
                self.cfg.agent_session_id, budget.prompts, budget.minutes * 60.0
            )
        except ControlStoreError as exc:
            self._control_error("approval budget unreadable; not asking", exc, call.name)
            return False

    def _use_scoped_grant(self, call: _Call) -> str | None:
        """A live scoped grant for this call, with one use spent; None if there's none."""
        try:
            grants = self.cfg.control.grants(server=self.cfg.server_name)
        except ControlStoreError as exc:
            self._control_error("grants unreadable; ignoring them", exc, call.name)
            return None
        for grant in grants:
            if not fnmatchcase(call.name, grant.tool):
                continue
            try:
                conditions = parse_conditions(grant.conditions)
            except ValueError:
                continue  # a grant we can't read grants nothing
            if conditions and not all_hold(conditions, call.args):
                continue
            try:
                if self.cfg.control.use_grant(grant.id):
                    return grant.id
            except ControlStoreError as exc:
                self._control_error("grant use not recorded; ignoring it", exc, call.name)
                return None
        return None

    def _quarantine(
        self,
        pending: Pending,
        result: dict[str, Any],
        detectors: str,
        findings: list[Finding],
        common: dict[str, Any],
    ) -> str | None:
        """Keep a withheld result for review; None if quarantine is off or failed."""
        if not self._controls.quarantine or pending.call_key is None:
            return None
        payload = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            qid = self.cfg.control.quarantine(
                session=self.cfg.agent_session_id,
                server=self.cfg.server_name,
                tool=pending.tool_name or "",
                call_key=pending.call_key,
                summary=detectors,
                payload=payload,
            )
        except ControlStoreError as exc:
            self._control_error("result not quarantined (still withheld)", exc, pending.tool_name)
            return None
        worst = max((f.severity for f in findings), key=_SEVERITY_RANK.__getitem__)
        self.emit.emit(
            EventType.RESPONSE_QUARANTINED,
            severity=worst,
            action=EventAction.BLOCKED,
            reason=f"withheld for review: {detectors}",
            details={"QuarantineId": qid, "Kept": len(payload) <= MAX_QUARANTINE_BYTES},
            result_bytes=len(payload),
            **common,
        )
        return qid

    async def _deliver_released(self, call: _Call, call_key: str) -> bool:
        """Answer a repeated call with its released result, without calling the server."""
        try:
            released = self.cfg.control.take_released(
                self.cfg.agent_session_id, self.cfg.server_name, call_key
            )
        except ControlStoreError as exc:
            self._control_error("released results unreadable", exc, call.name)
            return False
        if released is None:
            return False
        qid, payload = released
        try:
            result = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        if self._flow_mode() is not FlowMode.OFF:
            # It was withheld for a reason: whoever released it, it's untrusted input.
            error = self._flow_record(call.name, [Label.UNTRUSTED_INPUT])
            if error is not None:
                await self._reply_blocked_tool(call.frame.id, error, call.meta.present)
                return True
        self.emit.emit(
            EventType.RESPONSE_RELEASED,
            severity=Severity.MEDIUM,
            action=EventAction.ALLOWED,
            reason=f"delivered {qid} after human review",
            details={"QuarantineId": qid},
            result_bytes=len(payload),
            **call.common,
        )
        await self._reply_result(call.frame.id, result)
        return True

    def _effective_labels(self, tool: str, flow: _FlowCheck) -> frozenset[Label]:
        policy = self.cfg.policy.policy
        assert policy is not None
        return flow.tool_labels | policy.labels_for(self.cfg.server_name, tool)

    # ------------------------------------------------------------------ classifiers

    def _emit_verdict(
        self, runner: ClassifierRunner, verdict: Verdict, location: str, **ctx: Any
    ) -> None:
        s = runner.settings
        hit = verdict.hit(s.threshold)
        detector = f"classifier.{s.id}"
        rule = HIT_RULE if hit else (UNAVAILABLE_RULE if verdict.score is None else "no-hit")
        severity = Severity.INFORMATIONAL
        action = EventAction.NONE
        if is_enforcing(s) and verdict.score is None:
            severity, action = Severity.HIGH, EventAction.FAIL_CLOSED
        elif hit and s.mode is not ClassifierMode.SHADOW:
            severity = Severity(s.severity.value)
            action = EventAction.LOGGED if s.mode is ClassifierMode.ALERT else EventAction.NONE
        score = "none" if verdict.score is None else f"{verdict.score:.3f}"
        self.emit.emit(
            EventType.CLASSIFIER_VERDICT,
            severity=severity,
            action=action,
            detector_id=detector,
            rule_id=rule,
            match_summary=f"{s.kind.value} score {score} (threshold {s.threshold})",
            location=location,
            latency_ms=verdict.latency_ms,
            details={
                "Mode": s.mode.value,
                "Kind": s.kind.value,
                "Score": verdict.score,
                "Threshold": s.threshold,
                "Chunks": verdict.chunks,
                "Truncated": verdict.truncated,
                "Error": verdict.error,
            },
            **ctx,
        )
        if hit and s.mode is ClassifierMode.ALERT:
            # an alert-mode hit is a detection the SOC sees, but never a block
            for f in findings_for(s, verdict, location):
                self.emit.emit_finding(f, action=EventAction.LOGGED, **ctx)

    async def _background(self, fn: Callable[..., Coroutine[Any, Any, None]], *args: Any) -> None:
        if self.task_group is not None:
            self.task_group.start_soon(fn, *args)
        else:  # no task group (unit tests): run inline
            await fn(*args)

    async def _classify_background(
        self, runner: ClassifierRunner, value: Any, location: str, ctx: dict[str, Any]
    ) -> None:
        verdict = await runner.classify(value, location)
        self._emit_verdict(runner, verdict, location, **ctx)

    async def _classify(
        self, surface: ClassifierSurface, value: Any, location: str, **ctx: Any
    ) -> list[Finding]:
        """Enforce-mode findings for ``value``. Alert and shadow classifiers run alongside
        (in the task group, so they never delay the traffic) and only emit events."""
        runners = [r for r in self.cfg.classifiers if r.applies_to(surface)]
        if not runners:
            return []
        for r in runners:
            if not is_enforcing(r.settings):
                await self._background(self._classify_background, r, value, location, ctx)
        enforce = [r for r in runners if is_enforcing(r.settings)]
        verdicts: dict[str, Verdict] = {}

        async def one(r: ClassifierRunner) -> None:
            verdicts[r.settings.id] = await r.classify(value, location)

        async with anyio.create_task_group() as tg:
            for r in enforce:
                tg.start_soon(one, r)
        findings: list[Finding] = []
        for r in enforce:
            v = verdicts[r.settings.id]
            self._emit_verdict(r, v, location, **ctx)
            findings += findings_for(r.settings, v, location)
        return findings

    async def _classify_definitions(self, defs: list[dict[str, Any]]) -> dict[str, list[Finding]]:
        """Enforce-mode findings per tool name, from cached or fresh verdicts."""
        runners = [r for r in self.cfg.classifiers if r.applies_to(ClassifierSurface.DEFINITIONS)]
        out: dict[str, list[Finding]] = {}
        if not runners:
            return out
        todo: list[tuple[ClassifierRunner, str, str, dict[str, Any]]] = []
        for d in defs:
            name = as_str(d.get("name"))
            if name is None:
                continue
            digest = tool_digest(d)
            for r in runners:
                cached = self._definition_verdicts.get((r.settings.id, digest))
                if cached is None:
                    todo.append((r, name, digest, d))
                elif is_enforcing(r.settings):
                    out.setdefault(name, []).extend(
                        findings_for(r.settings, cached, f"tools[{name}]")
                    )

        async def one(r: ClassifierRunner, name: str, digest: str, d: dict[str, Any]) -> None:
            location = f"tools[{name}]"
            v = await r.classify(definition_text(d), location)
            if v.score is not None:  # never cache "no answer"
                self._definition_verdicts[(r.settings.id, digest)] = v
            self._emit_verdict(r, v, location, direction=_S2C, method=TOOLS_LIST, tool_name=name)
            if is_enforcing(r.settings):
                out.setdefault(name, []).extend(findings_for(r.settings, v, location))

        for t in todo:
            if not is_enforcing(t[0].settings):
                await self._background(one, *t)
        async with anyio.create_task_group() as tg:
            for t in todo:
                if is_enforcing(t[0].settings):
                    tg.start_soon(one, *t)
        return out

    def _provenance(self, tool: str, arguments: dict[str, Any], flow: _FlowCheck) -> list[Finding]:
        """Does this egress call carry a copy of private data the session read? (D-043)"""
        fp = self.cfg.fingerprinter
        if fp is None or Label.EGRESS not in self._effective_labels(tool, flow):
            return []
        try:
            found = self.cfg.flow.find(
                self.cfg.agent_session_id, "fp", argument_fingerprints(arguments, fp)
            )
        except FlowStoreError as exc:
            # Fail closed: treat the call as a copy made after untrusted input.
            flow.store_error = str(exc)
            self.emit.emit(
                EventType.INTERNAL_ERROR,
                severity=Severity.HIGH,
                action=EventAction.FAIL_CLOSED,
                tool_name=tool,
                reason=f"flow store unreadable; provenance unknown: {exc}",
                details={"Component": "flow_store"},
            )
            return [
                Finding(
                    detector_id=PROVENANCE_ID,
                    rule_id="provenance-unavailable",
                    severity=Severity.HIGH,
                    summary="provenance of the arguments could not be checked (flow store)",
                    location="arguments",
                )
            ]
        if not is_copy(found):
            return []
        sources = sorted({f"{s}/{t}" for s, t in found.values()})
        tainted = Label.UNTRUSTED_INPUT in flow.session_labels
        secret = any(v.startswith("k:") for v in found)
        return [
            Finding(
                detector_id=PROVENANCE_ID,
                rule_id="private-data-copied" if not secret else "private-secret-copied",
                severity=Severity.HIGH if tainted else Severity.MEDIUM,
                summary=(
                    f"arguments contain {'a secret' if secret else 'text'} copied from a "
                    f"private_data result ({', '.join(sources[:3])}; {len(found)} "
                    "fingerprints)" + ("; the session also read untrusted input" if tainted else "")
                ),
                location="arguments",
                mitre=("AML.T0086",),
                owasp=("LLM02",),
            )
        ]

    async def _record_private_result(self, pending: Pending, result: dict[str, Any]) -> str | None:
        """Fingerprint a private_data result before the agent sees it."""
        fp = self.cfg.fingerprinter
        if fp is None or Label.PRIVATE_DATA.value not in pending.flow_labels:
            return None
        fps = await anyio.to_thread.run_sync(result_fingerprints, result, fp)
        if not fps:
            return None
        try:
            self.cfg.flow.add(
                self.cfg.agent_session_id,
                "fp",
                fps,
                server=self.cfg.server_name,
                tool=pending.tool_name or "",
            )
        except FlowStoreError as exc:
            self.emit.emit(
                EventType.INTERNAL_ERROR,
                severity=Severity.HIGH,
                action=EventAction.FAIL_CLOSED,
                tool_name=pending.tool_name,
                reason=f"flow store unwritable; withholding a private result: {exc}",
                details={"Component": "flow_store"},
            )
            return "provenance of a private result could not be recorded (flow store unavailable)"
        return None

    def _flow_record(self, tool: str, labels: Iterable[Label]) -> str | None:
        """Add labels to the session before the call or result reaches its destination.
        Returns an error message if they could not be shared (the caller then blocks)."""
        labels = frozenset(labels)
        if not labels or self._flow_mode() is FlowMode.OFF:
            return None
        try:
            self.cfg.flow.add_labels(
                self.cfg.agent_session_id, labels, server=self.cfg.server_name, tool=tool
            )
        except FlowStoreError as exc:
            self.emit.emit(
                EventType.INTERNAL_ERROR,
                severity=Severity.HIGH,
                action=EventAction.FAIL_CLOSED,
                tool_name=tool,
                reason=f"flow store unwritable; blocking instead of losing labels: {exc}",
                details={"Component": "flow_store"},
            )
            return "session flow state could not be recorded (flow store unavailable)"
        return None

    def _emit_flow(self, flow: _FlowCheck, outcome: EventAction, common: dict[str, Any]) -> None:
        if not flow.violation:
            return
        blocked = outcome in (EventAction.BLOCKED, EventAction.DENIED)
        self.emit.emit(
            EventType.FLOW_RULE_OF_TWO,
            severity=Severity.HIGH if blocked else Severity.MEDIUM,
            action=outcome,
            reason=(
                "the call gives the agent session untrusted input, private data and a way to "
                f"act or send data out (flow mode {flow.mode.value})"
            ),
            details={
                "FlowMode": flow.mode.value,
                "SessionLabels": sorted(label.value for label in flow.session_labels),
                "ToolLabels": sorted(label.value for label in flow.tool_labels),
            },
            **common,
        )

    async def _tool_call(self, frame: Frame, params: dict[str, Any], meta: RequestMeta) -> None:
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

        call = _Call(
            frame=frame,
            name=name,
            args=args,
            risk="unknown",
            common={},
            args_bytes=len(json.dumps(args, ensure_ascii=False).encode("utf-8")),
            meta=meta,
            raw=frame.raw + b"\n",
        )
        self._redeem_approval_state(call, params)

        needs_listing = meta.present and (self.session.tools is None or self.session.tools_stale)
        needs_listing = needs_listing and self._policy_mode is not PinningMode.OFF
        if needs_listing and self.task_group is not None:
            self.task_group.start_soon(self._decide_call, call, needs_listing)
        else:
            await self._decide_call(call, needs_listing)

    def _redeem_approval_state(self, call: _Call, params: dict[str, Any]) -> None:
        """A retry carrying gatehouse's own requestState: verify it, read the user's
        answer, and strip gatehouse's fields so the server sees a plain request."""
        state = params.get("requestState")
        responses = as_obj(params.get("inputResponses"))
        ours = is_gatehouse_state(state)
        if ours:
            assert isinstance(state, str)
            signer = self.cfg.state_signer
            binding = call_binding(
                self.cfg.server_name, TOOLS_CALL, call.name, self._args_fp(call.args)
            )
            verified = signer.verify(state, binding) if signer is not None else None
            if verified is None:
                call.approval, call.approval_note = (
                    False,
                    "approval state invalid, expired or for another call",
                )
            elif verified.nonce in self.session.redeemed_states:
                call.approval, call.approval_note = False, "approval state already used (replay)"
            else:
                self.session.redeemed_states.add(verified.nonce)
                answer = responses.get(APPROVAL_KEY) if responses else None
                call.approval = is_approval(answer)
                call.approval_note = (
                    "approved by the user" if call.approval else "declined by the user"
                )
            rest = {k: v for k, v in (responses or {}).items() if k != APPROVAL_KEY}
            new_params = {
                k: v for k, v in params.items() if k not in ("requestState", "inputResponses")
            }
            if rest:
                new_params["inputResponses"] = rest
            new_obj = {**call.frame.obj, "params": new_params}
            call.raw = encode(new_obj)
            responses = rest or None
        if responses:
            call.answer_findings = self._answer_findings(responses)

    def _grant_key(self, call: _Call) -> str:
        return call_binding(self.cfg.server_name, TOOLS_CALL, call.name, self._args_fp(call.args))

    def _use_grant(self, call: _Call) -> bool:
        key = self._grant_key(call)
        grant = self.session.grants.get(key)
        if grant is None or grant.expires < time.monotonic() or grant.uses_left <= 0:
            self.session.grants.pop(key, None)
            return False
        grant.uses_left -= 1
        return True

    async def _decide_call(self, call: _Call, needs_listing: bool) -> None:
        frame = call.frame
        assert frame.id_key is not None
        if needs_listing:
            await self._refresh_tools(call.meta)
        info = self.session.tools.get(call.name) if self.session.tools else None
        call.risk = info.risk if info else classify(call.name)
        call.common = {
            "direction": _C2S,
            "method": TOOLS_CALL,
            "request_id": frame.id_key,
            "tool_name": call.name,
            "tool_risk": call.risk,
        }
        verdict = self._verdict(call.name, call.args, call.answer_findings)
        approved: bool | None = None
        if call.approval is not None:
            approved = call.approval
            verdict.reasons.append(call.approval_note or "")
            self.emit.emit(
                EventType.APPROVAL_GRANTED if approved else EventType.APPROVAL_DENIED,
                severity=Severity.LOW if approved else Severity.MEDIUM,
                action=EventAction.APPROVED if approved else EventAction.DENIED,
                reason=call.approval_note,
                details={"Channel": "mrtr"},
                **call.common,
            )
            if approved:
                self.session.grants[self._grant_key(call)] = Grant(
                    expires=time.monotonic() + GRANT_TTL_S, uses_left=GRANT_USES
                )
        elif verdict.action is Action.REQUIRE_APPROVAL and self._use_grant(call):
            approved = True
            verdict.reasons.append("covered by an approval granted for this exact call")
        if verdict.action is Action.REQUIRE_APPROVAL and approved is None and verdict.grantable:
            gid = self._use_scoped_grant(call)
            if gid is not None:
                approved = True
                verdict.reasons.append(f"covered by scoped grant {gid}")
                verdict.basis = "grant"
                self.emit.emit(
                    EventType.APPROVAL_GRANTED,
                    severity=Severity.LOW,
                    action=EventAction.APPROVED,
                    reason=f"scoped grant {gid}",
                    details={"Channel": "grant", "GrantId": gid},
                    **call.common,
                )

        if verdict.action is Action.REQUIRE_APPROVAL and approved is None:
            mrtr = (
                call.meta.present
                and call.meta.supports_elicitation_form()
                and self.cfg.state_signer is not None
            )
            legacy = (
                not call.meta.present
                and self._can_ask_for_approval()
                and self.task_group is not None
            )
            if (mrtr or legacy) and not self._spend_budget(call):
                verdict.action = Action.BLOCK
                verdict.basis = "approval_budget"
                verdict.reasons.append(
                    "approval budget used up for this session; a human can add a scoped "
                    "grant (`gatehouse grant add`) instead of approving each call"
                )
            elif mrtr:
                await self._ask_approval_mrtr(call, verdict)
                return
            elif legacy:
                assert self.task_group is not None
                self.task_group.start_soon(self._finish_call, call, verdict, None)
                return
        await self._finish_call(call, verdict, approved)

    async def _ask_approval_mrtr(self, call: _Call, verdict: _CallVerdict) -> None:
        signer = self.cfg.state_signer
        assert signer is not None
        reason = "; ".join(verdict.reasons) or "policy requires approval"
        req = ApprovalRequest(
            self.cfg.server_name, call.name, reason, tuple(sorted(call.args))[:32]
        )
        state = signer.issue(self._grant_key(call))
        self.emit.emit(
            EventType.APPROVAL_REQUESTED,
            severity=Severity.LOW,
            action=EventAction.APPROVAL_REQUIRED,
            reason=reason,
            details={"Channel": "mrtr"},
            **call.common,
        )
        await self._reply_result(
            call.frame.id, approval_input_required(elicitation_params(req), state)
        )

    def _can_ask_for_approval(self) -> bool:
        return self.approver is not None and self.session.client_supports_elicitation()

    async def _finish_call(self, call: _Call, verdict: _CallVerdict, approved: bool | None) -> None:
        frame = call.frame
        assert frame.id_key is not None
        fp = self.cfg.fingerprinter
        action = verdict.action
        revoked = False
        if action is Action.REQUIRE_APPROVAL:
            if approved is None and not call.meta.present:
                approved = await self._request_approval(call.name, call.args, verdict, call.common)
            action = Action.ALLOW if approved else Action.BLOCK
            if approved:
                # The server may have changed its tools while the user was deciding (a
                # rug pull timed to the approval prompt). Approval covers the tool the
                # user was shown, so re-check before forwarding.
                avail, avail_reason, avail_basis = self._availability(call.name)
                if avail is not Action.ALLOW:
                    action = Action.BLOCK
                    revoked = True
                    verdict.reasons.append(
                        f"{avail_reason or 'tool not available'} (after approval)"
                    )
                    verdict.basis = avail_basis or "unlisted_tool"
        elif approved is False and action is Action.ALLOW:
            approved = None  # a declined prompt for a call that no longer needs approval

        if action is Action.ALLOW and verdict.flow is not None:
            # The tool's labels join the session before the call is forwarded, so a call
            # on another server never sees a session older than this one.
            policy = self.cfg.policy.policy
            assert policy is not None
            effective = verdict.flow.tool_labels | policy.labels_for(
                self.cfg.server_name, call.name
            )
            call.flow_labels = frozenset(label.value for label in effective)
            error = self._flow_record(call.name, effective)
            if error is not None:
                action = Action.BLOCK
                approved = None
                verdict.reasons.append(error)
                verdict.basis = "flow"

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
        if revoked:
            outcome = EventAction.BLOCKED

        for f in verdict.findings:
            fa = self._finding_action(f)
            if f.detector_id == PROVENANCE_ID:
                # Its own event type (one per match), with the detection columns.
                self.emit.emit(
                    EventType.FLOW_PROVENANCE_MATCH,
                    severity=f.severity,
                    action=outcome,
                    detector_id=f.detector_id,
                    rule_id=f.rule_id,
                    match_summary=f.summary,
                    location=f.location,
                    mitre=list(f.mitre),
                    owasp=list(f.owasp),
                    details={"FindingAction": fa.value},
                    **call.common,
                )
                continue
            self.emit.emit_finding(
                f, action=outcome, details={"FindingAction": fa.value}, **call.common
            )
        if verdict.flow is not None:
            self._emit_flow(verdict.flow, outcome, call.common)
        self._maybe_strike(verdict.findings, call.name)

        reason = "; ".join(r for r in verdict.reasons if r) or None
        self.emit.emit(
            EventType.TOOL_CALL,
            severity=Severity.MEDIUM if action is Action.BLOCK else Severity.INFORMATIONAL,
            action=outcome,
            reason=reason,
            decision_basis=verdict.basis,
            policy_rule=verdict.policy_rule,
            arg_keys=sorted(call.args.keys())[:64],
            args_hmac=fp.json(call.args) if fp else None,
            args_bytes=call.args_bytes,
            details={
                "FindingCount": len(verdict.findings),
                **({"Principal": self.principal} if self.principal != "local" else {}),
            },
            **call.common,
        )

        if action is Action.ALLOW:
            call_key = self._grant_key(call)
            if await self._deliver_released(call, call_key):
                return
            self.client_pending[frame.id_key] = Pending(
                method=TOOLS_CALL,
                request_id=frame.id_key,
                tool_name=call.name,
                tool_risk=call.risk,
                args_bytes=call.args_bytes,
                modern=call.meta.present,
                version=call.meta.version,
                client_caps=call.meta.capabilities,
                flow_labels=call.flow_labels,
                call_key=call_key,
            )
            await self.to_server(call.raw)
        else:
            await self._reply_blocked_tool(
                frame.id, reason or "blocked by gatehouse policy", call.meta.present
            )

    async def _request_approval(
        self, tool: str, args: dict[str, Any], verdict: _CallVerdict, common: dict[str, Any]
    ) -> bool | None:
        """Legacy era. None: approval impossible (no approver / client can't elicit)."""
        approver = self.approver
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

    # ------------------------------------------------------------------ gatehouse's own requests

    async def _internal_request(self, method: str, params: dict[str, Any]) -> Frame | None:
        rid = INTERNAL_ID_PREFIX + uuid.uuid4().hex
        key = json.dumps(rid)
        waiter = _Waiter()
        self._internal[key] = waiter
        try:
            await self.to_server(
                encode({"jsonrpc": JSONRPC_VERSION, "id": rid, "method": method, "params": params})
            )
            with anyio.move_on_after(INTERNAL_TIMEOUT_S):
                await waiter.done.wait()
        finally:
            self._internal.pop(key, None)
        return waiter.frame

    async def _refresh_tools(self, meta: RequestMeta) -> None:
        """List tools upstream on the client's behalf (modern era, D-036).

        A stateless client may call a tool it listed in another process, or from its
        cache. gatehouse inspects a fresh listing before deciding, so pins and listing
        detectors still apply. The listing is not shown to the client.
        """
        assert meta.version is not None
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            params: dict[str, Any] = {"_meta": internal_meta(meta.version, meta.capabilities)}
            if cursor:
                params["cursor"] = cursor
            frame = await self._internal_request(TOOLS_LIST, params)
            result = as_obj(frame.obj.get("result")) if frame is not None else None
            if frame is None or result is None:
                self.emit.emit(
                    EventType.INTERNAL_ERROR,
                    severity=Severity.MEDIUM,
                    action=EventAction.FAIL_CLOSED,
                    method=TOOLS_LIST,
                    reason="gatehouse could not list the server's tools before a call "
                    + ("(timeout)" if frame is None else "(error response)"),
                )
                return
            pending = Pending(
                TOOLS_LIST, frame.id_key or "", has_cursor=cursor is not None, modern=True
            )
            await self._tools_list_result(frame, result, pending, deliver=False)
            cursor = as_str(result.get("nextCursor"))
            if not cursor:
                return

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
            await self._server_request(frame)
        else:
            await self._server_notification(frame)

    async def _server_request(self, frame: Frame) -> None:
        assert frame.id_key is not None and frame.method is not None
        method = frame.method
        params = as_obj(frame.obj.get("params")) or {}
        if self.session.era is Era.MODERN:
            # 2026-07-28: "The server MUST NOT write JSON-RPC requests"; MRTR replaces them.
            self.emit.emit(
                EventType.SERVER_REQUEST,
                severity=Severity.MEDIUM,
                action=EventAction.BLOCKED,
                direction=_S2C,
                method=method,
                request_id=frame.id_key,
                reason="server-initiated request on a 2026-07-28 connection (not allowed)",
            )
            await self.to_server(
                encode(
                    {
                        "jsonrpc": JSONRPC_VERSION,
                        "id": frame.id,
                        "error": {
                            "code": INVALID_REQUEST,
                            "message": "gatehouse: servers must not send requests "
                            "in protocol 2026-07-28",
                        },
                    }
                )
            )
            return
        findings: list[Finding] = []
        if method in INPUT_REQUEST_CAPABILITY:
            findings = inspect_server_request(method, params)
            if method == SAMPLING_CREATE and self._protocol.sampling is SamplingMode.BLOCK:
                findings.append(_sampling_blocked("params"))
        ctx: dict[str, Any] = {"direction": _S2C, "method": method, "request_id": frame.id_key}
        if self._worst(findings) is Action.BLOCK:
            self._emit_findings(findings, EventAction.BLOCKED, **ctx)
            self.emit.emit(
                EventType.SERVER_REQUEST,
                severity=Severity.MEDIUM,
                action=EventAction.BLOCKED,
                reason="server request withheld from the client",
                details={"FindingCount": len(findings)},
                **ctx,
            )
            if method == ELICITATION_CREATE:
                reply: dict[str, Any] = {
                    "jsonrpc": JSONRPC_VERSION,
                    "id": frame.id,
                    "result": {"action": "decline"},
                }
            else:
                reply = {
                    "jsonrpc": JSONRPC_VERSION,
                    "id": frame.id,
                    "error": {"code": INVALID_REQUEST, "message": "gatehouse: request blocked"},
                }
            await self.to_server(encode(reply))
            return
        self._emit_findings(findings, EventAction.LOGGED, **ctx)
        self.session.server_pending[frame.id_key] = Pending(method, frame.id_key)
        self.emit.emit(EventType.SERVER_REQUEST, severity=Severity.LOW, **ctx)
        await self.to_client(frame.raw + b"\n")

    async def _server_notification(self, frame: Frame) -> None:
        params = as_obj(frame.obj.get("params")) or {}
        meta = as_obj(params.get("_meta")) or {}
        method = frame.method or ""
        if META_SUBSCRIPTION_ID in meta:
            sub = meta[META_SUBSCRIPTION_ID]
            valid = isinstance(sub, str) or (isinstance(sub, int) and not isinstance(sub, bool))
            listen = self.client_pending.get(json.dumps(sub)) if valid else None
            problem: str | None = None
            if listen is None or listen.method != SUBSCRIPTIONS_LISTEN:
                problem = "notification for a subscription the client never opened"
            elif method != SUBSCRIPTIONS_ACKNOWLEDGED and method in _LISTEN_FILTER:
                wanted = (listen.listen_filter or {}).get(_LISTEN_FILTER[method])
                if not wanted:
                    problem = f"server sent {method} on a subscription that did not ask for it"
            if problem is not None:
                self.emit.emit(
                    EventType.PROTOCOL_UNSOLICITED_NOTIFICATION,
                    severity=Severity.LOW,
                    action=EventAction.BLOCKED,
                    direction=_S2C,
                    method=method,
                    reason=problem,
                )
                return
        if method == TOOLS_LIST_CHANGED:
            self.session.tools_stale = True
            self.emit.emit(EventType.TOOLS_LIST_CHANGED, severity=Severity.LOW, direction=_S2C)
        await self.to_client(frame.raw + b"\n")

    async def _server_response(self, frame: Frame) -> None:
        key = frame.id_key
        if key is not None and key in self._internal:
            waiter = self._internal[key]
            waiter.frame = frame
            waiter.done.set()
            return
        pending = self.client_pending.pop(key, None) if key is not None else None
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
        if result is not None and pending.modern:
            self._note_server(result)
            result_type = result.get("resultType")
            if result_type is None:
                if pending.method != DISCOVER or "supportedVersions" in result:
                    self._invalid_result(
                        pending,
                        "result has no resultType (treated as complete)",
                        Severity.LOW,
                        blocked=False,
                    )
            elif result_type == RESULT_INPUT_REQUIRED:
                if pending.method not in MRTR_METHODS:
                    self._invalid_result(
                        pending, f"input_required is not allowed for {pending.method}"
                    )
                    await self._reply_withheld(frame, pending, "invalid input_required result")
                    return
                await self._input_required(frame, result, pending)
                return
            elif result_type != RESULT_COMPLETE:
                # "A resultType of any value unrecognized by the client MUST be considered
                # invalid." gatehouse can't inspect what it can't parse: fail closed.
                self._invalid_result(pending, f"unknown resultType {str(result_type)[:40]!r}")
                await self._reply_withheld(frame, pending, "unknown resultType")
                return

        if pending.method == DISCOVER:
            if result is not None:
                await self._discover_result(frame, result, pending)
            else:
                await self._discover_failed(frame)
        elif pending.method == INITIALIZE and result is not None:
            await self._initialize_result(frame, result, pending)
        elif pending.method == TOOLS_LIST and result is not None:
            await self._tools_list_result(frame, result, pending)
        elif pending.method == TOOLS_CALL:
            await self._tool_result(frame, pending)
        elif result is not None and pending.modern and pending.method in CACHEABLE_METHODS:
            new = dict(result)
            if self._cap_ttl(new, pending.method):
                await self.to_client(encode({**frame.obj, "result": new}))
            else:
                await self.to_client(frame.raw + b"\n")
        else:
            await self.to_client(frame.raw + b"\n")

    def _invalid_result(
        self, pending: Pending, why: str, severity: Severity = Severity.HIGH, blocked: bool = True
    ) -> None:
        self.emit.emit(
            EventType.PROTOCOL_INVALID_RESULT,
            severity=severity,
            action=EventAction.BLOCKED if blocked else EventAction.LOGGED,
            direction=_S2C,
            method=pending.method,
            request_id=pending.request_id,
            reason=why,
        )

    def _cap_ttl(self, result: dict[str, Any], method: str) -> bool:
        """Lower ``ttlMs`` to the policy maximum. Returns True if ``result`` changed."""
        limit = self._protocol.max_ttl_ms
        ttl = result.get("ttlMs")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= limit:
            return False
        result["ttlMs"] = limit
        self.emit.emit(
            EventType.PROTOCOL_CACHE_HINT_CAPPED,
            severity=Severity.INFORMATIONAL,
            action=EventAction.REDACTED,
            direction=_S2C,
            method=method,
            reason=f"ttlMs {ttl} lowered to the policy maximum {limit}",
            details={"TtlMs": ttl, "MaxTtlMs": limit},
        )
        return True

    # ------------------------------------------------------------------ MRTR (2026-07-28)

    async def _input_required(self, frame: Frame, result: dict[str, Any], pending: Pending) -> None:
        caps = pending.client_caps or {}
        findings: list[Finding] = []
        methods: list[str] = []
        requests = result.get("inputRequests")
        state = result.get("requestState")
        if requests is not None and as_obj(requests) is None:
            findings.append(_shape("input-requests-not-object", "inputRequests must be an object"))
        for key, raw in list((as_obj(requests) or {}).items())[:64]:
            req = as_obj(raw)
            method = as_str(req.get("method")) if req is not None else None
            where = f"inputRequests[{str(key)[:64]}]"
            if req is None or method is None:
                findings.append(
                    _shape("malformed-input-request", "input request has no method", where)
                )
                continue
            methods.append(method[:64])
            cap = INPUT_REQUEST_CAPABILITY.get(method)
            if cap is not None and not isinstance(caps.get(cap), dict):
                findings.append(
                    _shape(
                        "undeclared-capability",
                        f"server asked for {method} but the request did not declare `{cap}`",
                        where,
                    )
                )
            if method == SAMPLING_CREATE and self._protocol.sampling is SamplingMode.BLOCK:
                findings.append(_sampling_blocked(where))
            for f in inspect_server_request(method, as_obj(req.get("params")) or {}):
                findings.append(f.model_copy(update={"location": f"{where}.{f.location}"}))
        if requests is None and state is None:
            findings.append(
                _shape(
                    "empty-input-required",
                    "input_required result with neither inputRequests nor requestState",
                    severity=Severity.LOW,
                )
            )
        if state is not None and not isinstance(state, str):
            findings.append(_shape("request-state-not-string", "requestState must be a string"))
        elif is_gatehouse_state(state):
            findings.append(
                _shape(
                    "forged-gatehouse-state",
                    "server returned a requestState that imitates gatehouse's own",
                    severity=Severity.HIGH,
                )
            )
        # Anything else the server put in the interim result (content the client ignores
        # today, or renders tomorrow) gets the result detectors too.
        rest = {
            k: v
            for k, v in result.items()
            if k not in ("inputRequests", "requestState", "resultType", "_meta")
        }
        if rest:
            findings += scan_tool_result(
                self.cfg.server_name, pending.tool_name or "", rest, self.cfg.scan
            )

        worst = self._worst(findings)
        blocked = worst is not Action.ALLOW  # no approval after the fact: withhold
        outcome = (
            EventAction.BLOCKED
            if blocked
            else (EventAction.LOGGED if findings else EventAction.ALLOWED)
        )
        ctx: dict[str, Any] = {
            "direction": _S2C,
            "method": pending.method,
            "request_id": pending.request_id,
            "tool_name": pending.tool_name,
            "tool_risk": pending.tool_risk,
        }
        self._emit_findings(findings, outcome, **ctx)
        self.emit.emit(
            EventType.SERVER_INPUT_REQUIRED,
            severity=Severity.MEDIUM if blocked else Severity.LOW,
            action=outcome,
            details={
                "Methods": methods[:16],
                "HasRequestState": state is not None,
                "FindingCount": len(findings),
            },
            **ctx,
        )
        if blocked:
            rules = ", ".join(sorted({f"{f.detector_id}/{f.rule_id}" for f in findings}))
            await self._reply_withheld(frame, pending, f"server input request withheld ({rules})")
        else:
            await self.to_client(frame.raw + b"\n")

    # ------------------------------------------------------------------ era, versions, downgrades

    def _pinned_versions(self) -> tuple[str, ...]:
        if self._policy_mode is PinningMode.OFF:
            return ()
        store = self._load_pins()
        proto = store.server(self.cfg.server_name).protocol if store is not None else None
        return tuple(proto.versions) if proto is not None else ()

    def _record_versions(self, versions: tuple[str, ...]) -> None:
        if self._policy_mode is PinningMode.OFF or not versions:
            return
        try:
            pin_protocol(self.cfg.pins_path, self.cfg.server_name, versions)
        except (PinStoreError, OSError) as exc:
            self.emit.emit(
                EventType.PIN_STORE_ERROR,
                severity=Severity.HIGH,
                reason=f"could not record protocol versions: {exc}",
            )

    def _downgrade(self, finding: Finding) -> bool:
        """Report a downgrade; True if the policy refuses it."""
        refuse = not self._protocol.allow_downgrade
        self.emit.emit_finding(
            finding,
            action=EventAction.BLOCKED if refuse else EventAction.LOGGED,
            direction=_S2C,
        )
        if refuse:
            self.session.downgrade_blocked = True
        return refuse

    async def _discover_result(
        self, frame: Frame, result: dict[str, Any], pending: Pending
    ) -> None:
        new = dict(result)
        modified = False
        raw_versions = as_list(result.get("supportedVersions")) or []
        versions = [v for v in raw_versions if isinstance(v, str)]
        keep = [v for v in versions if v in ALL_VERSIONS]
        if keep != raw_versions:
            new["supportedVersions"] = keep
            modified = True
        offered_modern = tuple(v for v in keep if v in MODERN_VERSIONS)
        self.session.offered_versions = tuple(keep)
        finding = detect_downgrade(self._pinned_versions(), offered_versions=keep)
        if finding is not None:
            self._downgrade(finding)
        else:
            self._record_versions(offered_modern)
            # A successful modern probe opens a 2026-07-28 connection, as it does at the
            # server (the opening request decides the era).
            if pending.version in offered_modern and self.session.era is None:
                self.session.era = Era.MODERN

        instructions = as_str(result.get("instructions"))
        if instructions:
            findings = detect_instruction_injection(instructions)
            worst = self._worst(findings)
            self._emit_findings(
                findings,
                EventAction.REDACTED if worst is Action.BLOCK else EventAction.LOGGED,
                _S2C,
                method=DISCOVER,
            )
            if worst is Action.BLOCK:
                del new["instructions"]
                modified = True
        modified |= self._cap_ttl(new, DISCOVER)
        self.emit.emit(
            EventType.PROTOCOL_NEGOTIATED,
            direction=_S2C,
            method=DISCOVER,
            details={
                "SupportedVersions": keep[:16],
                "Removed": [str(v)[:32] for v in raw_versions if v not in keep][:16],
            },
        )
        if modified:
            await self.to_client(encode({**frame.obj, "result": new}))
        else:
            await self.to_client(frame.raw + b"\n")

    async def _discover_failed(self, frame: Frame) -> None:
        error = as_obj(frame.obj.get("error")) or {}
        if error.get("code") != UNSUPPORTED_PROTOCOL_VERSION:  # -32022 is a modern answer
            finding = detect_downgrade(self._pinned_versions(), discover_failed=True)
            if finding is not None:
                self._downgrade(finding)
        await self.to_client(frame.raw + b"\n")

    async def _initialize_result(
        self, frame: Frame, result: dict[str, Any], pending: Pending
    ) -> None:
        version = as_str(result.get("protocolVersion"))
        info = as_obj(result.get("serverInfo")) or {}
        self.emit.context.upstream_name = as_str(info.get("name"))
        self.emit.context.upstream_version = as_str(info.get("version"))
        if version is None or version not in LEGACY_VERSIONS:
            self.session.version_rejected = True
            self.emit.emit(
                EventType.PROTOCOL_UNSUPPORTED_VERSION,
                severity=Severity.HIGH,
                action=EventAction.BLOCKED,
                direction=_S2C,
                method=INITIALIZE,
                reason=f"negotiated protocol version {version!r} is not supported by gatehouse",
                details={"Supported": list(LEGACY_VERSIONS)},
            )
            await self._reply_error(
                frame.id,
                UNSUPPORTED_PROTOCOL_VERSION,
                "gatehouse: unsupported protocol version",
                {"supported": list(LEGACY_VERSIONS), "requested": version},
            )
            return
        finding = detect_downgrade(
            self._pinned_versions(), requested=pending.requested_version, negotiated=version
        )
        if finding is not None and self._downgrade(finding):
            self.session.version_rejected = True
            await self._reply_error(
                frame.id,
                UNSUPPORTED_PROTOCOL_VERSION,
                "gatehouse: protocol downgrade refused",
                {"supported": [pending.requested_version], "requested": version},
            )
            return
        if self.session.era is Era.MODERN:
            # The server accepted a handshake on a connection that is already serving
            # 2026-07-28 requests: two eras at once is not something gatehouse inspects.
            self._invalid_result(pending, "initialize succeeded on a 2026-07-28 connection")
            await self._reply_error(
                frame.id,
                UNSUPPORTED_PROTOCOL_VERSION,
                "connection is serving the 2026-07-28 protocol",
                {"supported": list(MODERN_VERSIONS), "requested": pending.requested_version},
            )
            return
        self.session.era = Era.LEGACY
        self._record_versions((version,))
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
        self, frame: Frame, result: dict[str, Any], pending: Pending, *, deliver: bool = True
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
        classified = await self._classify_definitions(defs)

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

            # content detectors on the definition (M2), x-mcp-header checks (2026-07-28)
            findings = scan_tool_definition(tdef, defs, self.cfg.scan)
            findings += classified.get(name, [])
            header_findings = x_mcp_headers(tdef)[1]
            if not self.cfg.http:
                # stdio clients MAY ignore x-mcp-header; report, don't filter, on stdio
                header_findings = [
                    f.model_copy(update={"severity": Severity.LOW})
                    if f.detector_id == HEADER_ID and f.rule_id == "invalid-annotation"
                    else f
                    for f in header_findings
                ]
            findings += header_findings
            worst = self._worst(findings)
            if self.cfg.http and any(f.rule_id == "invalid-annotation" for f in header_findings):
                worst = Action.BLOCK  # "the client MUST exclude the invalid tool"
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
                "ListedBy": "client" if deliver else "gatehouse",
            },
        )
        if not deliver:
            return

        new_result = dict(result)
        modified = bool(filtered) or raw_tools is None
        if modified:
            new_result["tools"] = kept
            if pending.modern and "cacheScope" in new_result:
                # The listing now reflects this gatehouse's policy decisions: it must not
                # be served from a shared cache to callers behind a different policy.
                new_result["cacheScope"] = "private"
        if pending.modern:
            modified |= self._cap_ttl(new_result, TOOLS_LIST)
        if modified:
            await self.to_client(encode({**frame.obj, "result": new_result}))
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
            findings += await self._classify(
                ClassifierSurface.RESULTS,
                result,
                "result",
                direction=_S2C,
                method=TOOLS_CALL,
                tool_name=pending.tool_name,
            )
        worst = self._worst(findings)
        # Approval is not possible after the fact: a flagged result is withheld.
        blocked = worst is not Action.ALLOW
        flow_error: str | None = None
        kill = self._kill_switch()
        if kill is not None:
            blocked = True
            flow_error = f"kill switch engaged: {kill.reason}"
        if not blocked and any(f.detector_id in _INJECTION_DETECTORS for f in findings):
            # Whatever the tool's labels say, a result with injected instructions in it is
            # untrusted input once the agent reads it.
            flow_error = self._flow_record(pending.tool_name or "", [Label.UNTRUSTED_INPUT])
            blocked = flow_error is not None
        if not blocked and result is not None and pending.flow_labels:
            flow_error = await self._record_private_result(pending, result)
            blocked = flow_error is not None
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
        self._maybe_strike(findings, pending.tool_name or "")
        if blocked:
            detectors = ", ".join(sorted({f"{f.detector_id}/{f.rule_id}" for f in findings}))
            qid = None
            if flow_error is None and result is not None:
                qid = self._quarantine(pending, result, detectors, findings, common)
            if qid is not None:
                await self._reply_tool_text(
                    frame.id,
                    f"[gatehouse] Tool result withheld for review (id {qid}): {detectors}. "
                    f"Ask the user to review it with `gatehouse review show {qid}`. If they "
                    "release it, repeat the same call to receive it.",
                    pending.modern,
                )
            else:
                await self._reply_blocked_tool(
                    frame.id, f"tool result withheld ({flow_error or detectors})", pending.modern
                )
        else:
            await self.to_client(frame.raw + b"\n")

    # ------------------------------------------------------------------ lifecycle

    async def upstream_exited(self, returncode: int | None) -> None:
        self.emit.emit(
            EventType.UPSTREAM_EXITED,
            severity=Severity.LOW,
            details={"ReturnCode": returncode, "PendingRequests": len(self.client_pending)},
        )
        for waiter in self._internal.values():
            waiter.done.set()
        for key, pending in list(self.client_pending.items()):
            del self.client_pending[key]
            await self._reply_error(
                json.loads(key),
                UPSTREAM_UNAVAILABLE,
                f"gatehouse: upstream server exited ({pending.method})",
            )


_INJECTION_DETECTORS = frozenset({"response.injection", "text.invisible"})
PROVENANCE_ID = "flow.provenance"
# Findings about gatehouse's own state, not the agent's behaviour: no breaker strike.
_NOT_STRIKES = frozenset({"provenance-unavailable", UNAVAILABLE_RULE})
_SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _shape(
    rule: str, summary: str, where: str = "result", severity: Severity = Severity.HIGH
) -> Finding:
    return Finding(
        detector_id=SHAPE_ID,
        rule_id=rule,
        severity=severity,
        summary=summary,
        location=where,
        mitre=("AML.T0053",),
        owasp=("LLM06",),
    )


def _sampling_blocked(where: str) -> Finding:
    return Finding(
        detector_id="server_request.sampling",
        rule_id="sampling-blocked-by-policy",
        severity=Severity.HIGH,
        summary="the policy refuses server sampling requests (protocol.sampling: block)",
        location=where,
        mitre=("AML.T0051",),
        owasp=("LLM01",),
    )


__all__ = ["METHOD_NOT_FOUND", "Approver", "Router", "RouterConfig", "Send", "strictest"]
