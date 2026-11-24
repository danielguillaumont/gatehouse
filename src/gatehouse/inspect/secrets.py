"""Secret catalog, secret detection in tool arguments, and masking.

Patterns are written to be linear-time with Python's ``re``: no nested quantifiers, all
repetition bounded, and inputs are size-capped by ``inspect.walk``. Rule ideas follow the
public gitleaks / detect-secrets catalogs; patterns here are written from scratch.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.walk import WalkStats, iter_strings

DETECTOR_ID = "args.secrets"
_MITRE = ("AML.T0086", "T1552")
_OWASP = ("LLM02",)


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    description: str
    pattern: re.Pattern[str]
    severity: Severity
    group: int = 1  # capture group holding the secret value
    # Lower-case literals; the regex only runs if one occurs in the lower-cased text.
    # Every match of ``pattern`` must contain one of them (tested), so this is a pure
    # speed-up (gitleaks-style keyword prefilter). Empty = always run.
    keywords: tuple[str, ...] = ()


def _r(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Order matters only for overlapping matches: more specific rules first.
SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private-key",
        "PEM private key header",
        _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
        Severity.CRITICAL,
        keywords=("private key",),
    ),
    SecretRule(
        "aws-access-key-id",
        "AWS access key ID",
        _r(r"(?<![A-Za-z0-9])((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})(?![A-Za-z0-9])"),
        Severity.HIGH,
        keywords=("akia", "asia", "abia", "acca"),
    ),
    SecretRule(
        "aws-secret-access-key",
        "AWS secret access key (with context)",
        _r(
            r"aws.{0,20}?(?:secret|sk).{0,20}?[\"'=:\s]{1,5}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        keywords=("aws",),
    ),
    SecretRule(
        "github-token",
        "GitHub token",
        _r(r"(?<![A-Za-z0-9])(gh[pousr]_[A-Za-z0-9]{36,255})(?![A-Za-z0-9])"),
        Severity.HIGH,
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    ),
    SecretRule(
        "github-fine-grained-pat",
        "GitHub fine-grained personal access token",
        _r(r"(?<![A-Za-z0-9])(github_pat_[A-Za-z0-9_]{50,255})"),
        Severity.HIGH,
        keywords=("github_pat_",),
    ),
    SecretRule(
        "gitlab-pat",
        "GitLab personal access token",
        _r(r"(?<![A-Za-z0-9])(glpat-[A-Za-z0-9_\-]{20,64})"),
        Severity.HIGH,
        keywords=("glpat-",),
    ),
    SecretRule(
        "slack-token",
        "Slack token",
        _r(r"(?<![A-Za-z0-9])(xox[abprs]-[A-Za-z0-9-]{10,250})"),
        Severity.HIGH,
        keywords=("xox",),
    ),
    SecretRule(
        "slack-webhook",
        "Slack incoming webhook URL",
        _r(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,200})"),
        Severity.HIGH,
        keywords=("hooks.slack.com",),
    ),
    SecretRule(
        "stripe-live-key",
        "Stripe live secret/restricted key",
        _r(r"(?<![A-Za-z0-9])((?:sk|rk)_live_[A-Za-z0-9]{20,250})"),
        Severity.CRITICAL,
        keywords=("_live_",),
    ),
    SecretRule(
        "google-api-key",
        "Google API key",
        _r(r"(?<![A-Za-z0-9])(AIza[0-9A-Za-z_\-]{35})"),
        Severity.HIGH,
        keywords=("aiza",),
    ),
    SecretRule(
        "anthropic-api-key",
        "Anthropic API key",
        _r(r"(?<![A-Za-z0-9])(sk-ant-[A-Za-z0-9_\-]{20,250})"),
        Severity.HIGH,
        keywords=("sk-ant-",),
    ),
    SecretRule(
        "openai-api-key",
        "OpenAI-style API key",
        _r(r"(?<![A-Za-z0-9])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,250})"),
        Severity.HIGH,
        keywords=("sk-",),
    ),
    SecretRule(
        "azure-storage-account-key",
        "Azure Storage account key in a connection string",
        _r(r"(AccountKey=[A-Za-z0-9+/]{86}==)", re.IGNORECASE),
        Severity.CRITICAL,
        keywords=("accountkey=",),
    ),
    SecretRule(
        "azure-sas-signature",
        "Azure shared access signature",
        _r(r"[?&](sig=[A-Za-z0-9%+/]{30,200}(?:%3D|=){0,2})", re.IGNORECASE),
        Severity.HIGH,
        keywords=("sig=",),
    ),
    SecretRule(
        "entra-client-secret",
        "Microsoft Entra ID application client secret",
        _r(
            r"(?<![A-Za-z0-9_~.\-])([A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{31,34})(?![A-Za-z0-9_~.\-])"
        ),
        Severity.HIGH,
        keywords=("q~",),
    ),
    SecretRule(
        "jwt",
        "JSON Web Token (bearer credential)",
        _r(
            r"(?<![A-Za-z0-9])(eyJ[A-Za-z0-9_\-]{8,4096}\.eyJ[A-Za-z0-9_\-]{8,8192}\.[A-Za-z0-9_\-]{8,4096})"
        ),
        Severity.HIGH,
        keywords=("eyj",),
    ),
    SecretRule(
        "url-credentials",
        "Credentials embedded in a URL",
        _r(
            r"\b([a-z][a-z0-9+.\-]{1,20}://[^\s:/@]{1,64}:[^\s:/@]{3,128}@[^\s/]{1,255})",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        keywords=("://",),
    ),
    SecretRule(
        "generic-assignment",
        "Password/secret/API key assigned a literal value",
        _r(
            r"(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token)\s{0,3}[:=]\s{0,3}"
            r"[\"']?([^\s\"']{8,128})",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        keywords=("password", "passwd", "pwd", "secret", "api", "access"),
    ),
)


def mask(value: str) -> str:
    """Show just enough to recognize a secret, never enough to use it."""
    if len(value) >= 20:
        return f"{value[:4]}{'*' * min(len(value) - 8, 24)}{value[-4:]}"
    if len(value) >= 8:
        return f"{value[:2]}{'*' * (len(value) - 2)}"
    return "*" * len(value)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    rule: SecretRule
    start: int
    end: int
    value: str


def find_secrets(text: str) -> list[SecretMatch]:
    """All non-overlapping secret matches in ``text`` (earliest rule wins on overlap)."""
    taken: list[tuple[int, int]] = []
    found: list[SecretMatch] = []
    lowered = text.lower()
    for rule in SECRET_RULES:
        if rule.keywords and not any(k in lowered for k in rule.keywords):
            continue
        for m in rule.pattern.finditer(text):
            start, end = m.span(rule.group)
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            taken.append((start, end))
            found.append(SecretMatch(rule, start, end, m.group(rule.group)))
    found.sort(key=lambda s: s.start)
    return found


def redact_text(text: str) -> str:
    """Replace every secret in ``text`` with its masked form."""
    matches = find_secrets(text)
    if not matches:
        return text
    out: list[str] = []
    cursor = 0
    for m in matches:
        out.append(text[cursor : m.start])
        out.append(mask(m.value))
        cursor = m.end
    out.append(text[cursor:])
    return "".join(out)


Fingerprinter = Callable[[str], str]


def detect_secrets(
    value: object,
    root: str,
    fingerprint: Fingerprinter | None = None,
    stats: WalkStats | None = None,
) -> list[Finding]:
    """Scan every string (and key) in ``value`` for secrets."""
    findings: list[Finding] = []
    for where, text in iter_strings(value, root, stats):
        for m in find_secrets(text):
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    rule_id=m.rule.rule_id,
                    severity=m.rule.severity,
                    summary=f"{m.rule.description}: {mask(m.value)}",
                    location=where,
                    mitre=_MITRE,
                    owasp=_OWASP,
                    fingerprint=fingerprint(m.value) if fingerprint else None,
                )
            )
    return findings
