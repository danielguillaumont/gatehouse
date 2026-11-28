"""Credential stores and sensitive system files referenced in tool arguments.

Paths are normalized first: backslashes become ``/``, the text is case-folded, and
``.``/``..`` segments are collapsed. So ``C:\\Windows\\System32\\config\\SAM``,
``~/.SSH/id_rsa`` and ``docs/../../.env`` are all seen as what they are. Template or
example files (``.env.example``) are not flagged.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.rules import PatternRule, scan

DETECTOR_ID = "args.paths"
_MITRE = ("AML.T0098", "T1552")
_OWASP = ("LLM02", "LLM06")


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)  # input is already case-folded


_END = r"(?=$|[\s\"'`;|&)<>,])"

PATH_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "ssh-private-key",
        "SSH private key or SSH directory",
        _c(
            r"(?:^|[/\s\"'=])\.ssh/(?:id_[a-z0-9_]{1,20}(?!\.pub)|identity|authorized_keys)"
            + _END
            + r"|(?:^|[/\s\"'=])id_(?:rsa|dsa|ecdsa|ed25519)"
            + _END
        ),
        Severity.HIGH,
        (".ssh", "id_"),
        ("AML.T0098", "T1552.004"),
        _OWASP,
    ),
    PatternRule(
        "cloud-credentials",
        "cloud or tool credential file",
        _c(
            r"\.aws/(?:credentials|config)"
            + _END
            + r"|\.azure/(?:accesstokens\.json|msal_token_cache)"
            r"|\.config/gcloud/(?:credentials\.db|application_default_credentials\.json)"
            r"|\.kube/config"
            + _END
            + r"|\.docker/config\.json|\.git-credentials"
            + _END
            + r"|(?:^|/)\.(?:npmrc|pypirc|netrc|pgpass)"
            + _END
            + r"|(?:^|/)(?:\.cursor|\.claude|\.codeium/windsurf|claude)/"
            r"(?:mcp|claude_desktop_config)\.json" + r"|(?:^|/)mcp\.json" + _END
        ),
        Severity.HIGH,
        (
            ".aws",
            ".azure",
            "gcloud",
            ".kube",
            ".docker",
            "credentials",
            "npmrc",
            "pypirc",
            "netrc",
            "pgpass",
            "mcp",
            "claude",
        ),
        ("AML.T0098", "T1552.001"),
        _OWASP,
    ),
    PatternRule(
        "credential-directory",
        "a whole credential directory or a glob over one (~/.ssh, ~/.aws/*, ~/.gnupg)",
        _c(
            r"(?:^|[/\s\"'=~])\.(?:ssh|aws|gnupg|azure|kube|password-store)"
            r"(?:/\*{1,2}(?:\.\*|/\*)?)?/?"
            + _END
            + r"|(?:^|[/\s\"'=~])\.config/gcloud(?:/\*{1,2})?/?"
            + _END
            + r"|(?:^|[/\s\"'=~])\.ssh/id_\*"
            + _END
        ),
        Severity.HIGH,
        (".ssh", ".aws", ".gnupg", ".azure", ".kube", ".password-store", "gcloud"),
        ("AML.T0098", "T1552.004"),
        _OWASP,
    ),
    PatternRule(
        "dotenv",
        "environment file with secrets (.env)",
        _c(
            r"(?:^|[/\s\"'=])\.env(?:\.(?:local|prod|production|dev|development|staging|test))?"
            + _END
        ),
        Severity.HIGH,
        (".env",),
        _MITRE,
        _OWASP,
    ),
    PatternRule(
        "os-credential-store",
        "operating-system credential or password store",
        _c(
            r"/etc/(?:shadow|gshadow|sudoers|master\.passwd)"
            + _END
            + r"|/windows/system32/config/(?:sam|security|system)"
            + _END
            + r"|/windows/ntds/ntds\.dit|/library/keychains/|login\.keychain"
        ),
        Severity.HIGH,
        ("/etc/", "system32/config", "ntds", "keychain"),
        ("AML.T0098", "T1003"),
        _OWASP,
    ),
    PatternRule(
        "browser-secrets",
        "browser cookie or saved-password store",
        _c(
            r"/(?:user data|chrome|chromium|edge|brave[^/]{0,20})/[^\"'\n]{0,120}?"
            r"/(?:cookies|login data|web data)"
            + _END
            + r"|/firefox/profiles/[^\"'\n]{0,120}?/(?:cookies\.sqlite|logins\.json|key4\.db)"
        ),
        Severity.HIGH,
        ("cookies", "login data", "web data", "logins.json", "key4.db"),
        ("AML.T0098", "T1539", "T1555.003"),
        _OWASP,
    ),
)


def normalize_path_text(text: str) -> str:
    s = text.replace("\\", "/").casefold()
    while "//" in s:
        s = s.replace("//", "/")
    if "/./" in s or "/../" in s or s.startswith(("./", "../")):
        # collapse per whitespace-separated token so commands keep their shape
        s = " ".join(
            posixpath.normpath(tok) if "/" in tok and ".." in tok else tok for tok in s.split(" ")
        )
    return s


def detect_paths(strings: Iterable[tuple[str, str]]) -> list[Finding]:
    return scan(
        DETECTOR_ID, ((where, normalize_path_text(text)) for where, text in strings), PATH_RULES
    )
