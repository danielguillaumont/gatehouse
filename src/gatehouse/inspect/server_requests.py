"""Requests a *server* makes of the client: elicitation, sampling, roots.

In MCP 2026-07-28 they arrive inside an ``InputRequiredResult`` (MRTR); in the legacy
era as server-initiated JSON-RPC requests. Either way the content is server-controlled:

- **elicitation** asks the *user* something. The spec forbids form mode for secrets
  ("Servers MUST NOT use form mode elicitation to request sensitive information such as
  passwords, API keys, access tokens, or payment credentials"), so a form asking for one
  is phishing. A prompt that mentions gatehouse imitates gatehouse's own approval prompt.
- **sampling** puts server text into the client's LLM: scanned like a tool result.
- **roots** carries no server text.

Pure functions; the router decides what to do with the findings.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, cast
from urllib.parse import urlsplit

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.injection import detect_injection
from gatehouse.inspect.invisible import detect_invisible
from gatehouse.inspect.walk import WalkStats, iter_strings
from gatehouse.jsonutil import as_obj, as_str
from gatehouse.protocol import ELICITATION_CREATE, ROOTS_LIST, SAMPLING_CREATE

DETECTOR_ID = "server_request.elicitation"
SAMPLING_ID = "server_request.sampling"
SHAPE_ID = "server_request.shape"

_PHISH_MITRE = ("AML.T0098", "T1056.002")  # GUI Input Capture
_PHISH_OWASP = ("LLM01", "LLM02")

# Credential-like words in a form's field names, titles, descriptions or message.
# Bounded alternation with optional single separators: linear time.
_CREDENTIAL = re.compile(
    r"(?<![a-z])(?:pass[\s_-]?(?:word|phrase|code)|passwd|pwd|"
    r"api[\s_-]?(?:key|token|secret)|access[\s_-]?(?:key|token)|auth[\s_-]?token|"
    r"bearer[\s_-]?token|refresh[\s_-]?token|session[\s_-]?(?:token|cookie)|"
    r"secret[\s_-]?key|client[\s_-]?secret|private[\s_-]?key|ssh[\s_-]?key|"
    r"seed[\s_-]?phrase|recovery[\s_-]?(?:phrase|code)|mnemonic|"
    r"one[\s_-]?time[\s_-]?(?:code|password)|otp|2fa|mfa[\s_-]?code|"
    r"verification[\s_-]?code|security[\s_-]?code|cvv|cvc|"
    r"card[\s_-]?number|credit[\s_-]?card|iban|ssn|social[\s_-]?security)(?![a-z])",
    re.IGNORECASE,
)
_GATEHOUSE = re.compile(r"gate[\s_-]?house", re.IGNORECASE)
MAX_TEXT_CHARS = 20_000


def _form_texts(params: Mapping[str, Any]) -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = []
    message = as_str(params.get("message"))
    if message:
        texts.append(("message", message[:MAX_TEXT_CHARS]))
    schema = as_obj(params.get("requestedSchema")) or {}
    props = as_obj(schema.get("properties")) or {}
    for key, raw in list(props.items())[:200]:
        texts.append((f"requestedSchema.properties[{key}]", key))
        prop = as_obj(raw) or {}
        for attr in ("title", "description"):
            value = as_str(prop.get(attr))
            if value:
                texts.append((f"requestedSchema.properties[{key}].{attr}", value[:2000]))
    return texts


def _url_findings(url: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return [_phish("invalid-url", "URL-mode elicitation with an unparseable URL", "url")]
    if parts.scheme.lower() != "https":
        findings.append(
            _phish(
                "non-https-url",
                f"URL-mode elicitation over {parts.scheme!r}",
                "url",
                Severity.MEDIUM,
            )
        )
    if "@" in parts.netloc:
        findings.append(
            _phish("userinfo-in-url", "URL hides its real host behind user@ (phishing)", "url")
        )
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(
            _phish("punycode-host", f"URL host is punycode ({host})", "url", Severity.MEDIUM)
        )
    if re.fullmatch(r"[0-9.]{7,15}|\[?[0-9a-f:]{2,39}\]?", host):
        findings.append(
            _phish("ip-literal-host", "URL host is an IP address", "url", Severity.MEDIUM)
        )
    return findings


def _phish(rule: str, summary: str, where: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        detector_id=DETECTOR_ID,
        rule_id=rule,
        severity=severity,
        summary=summary,
        location=where,
        mitre=_PHISH_MITRE,
        owasp=_PHISH_OWASP,
    )


def inspect_elicitation(params: Mapping[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    mode = as_str(params.get("mode")) or "form"
    texts = _form_texts(params)
    for where, text in texts:
        if _GATEHOUSE.search(text):
            findings.append(
                _phish(
                    "mentions-gatehouse",
                    "server prompt mentions gatehouse: it can imitate a gatehouse approval",
                    where,
                )
            )
            break
    if mode == "form":
        for where, text in texts:
            m = _CREDENTIAL.search(text)
            if m:
                findings.append(
                    _phish(
                        "form-asks-for-credential",
                        f"form-mode elicitation asks for a credential ({m.group(0)!r}); "
                        "the spec requires URL mode for secrets",
                        where,
                    )
                )
                break
    elif mode == "url":
        url = as_str(params.get("url"))
        if url:
            findings += _url_findings(url[:4000])
    else:
        findings.append(
            _phish("unknown-mode", f"unknown elicitation mode {mode!r}", "mode", Severity.MEDIUM)
        )
    findings += detect_invisible(texts)
    return findings


def inspect_sampling(params: Mapping[str, Any]) -> list[Finding]:
    """Server-written messages and system prompt for the client's model."""
    payload = {
        "systemPrompt": params.get("systemPrompt"),
        "messages": params.get("messages"),
    }
    return [f.model_copy(update={"detector_id": SAMPLING_ID}) for f in detect_injection(payload)]


def inspect_server_request(method: str, params: Mapping[str, Any]) -> list[Finding]:
    if method == ELICITATION_CREATE:
        return inspect_elicitation(params)
    if method == SAMPLING_CREATE:
        return inspect_sampling(params)
    if method == ROOTS_LIST:
        return []
    return [
        Finding(
            detector_id=SHAPE_ID,
            rule_id="unknown-input-request",
            severity=Severity.HIGH,
            summary=f"server asked the client for {method[:64]!r}, which is not an MRTR "
            "input request type (elicitation, sampling, roots)",
            location="method",
            mitre=("AML.T0053",),
            owasp=("LLM06",),
        )
    ]


def answer_texts(value: object) -> list[tuple[str, str]]:
    """Strings a client sends back in answer to server requests (for secret scanning)."""
    return list(iter_strings(cast(Any, value), "inputResponses", WalkStats(), include_keys=False))
