"""Dangerous shell commands in tool arguments.

Runs on every string argument of every tool, not only on tools whose name says ``exec``:
names are attacker-controlled (docs/policy.md). Each rule targets a specific behaviour
with low false-positive risk on everyday commands: ``rm -rf build/`` is fine,
``rm -rf /`` is not.
"""

from __future__ import annotations

from collections.abc import Iterable

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.rules import PatternRule, ci, scan

DETECTOR_ID = "args.commands"
_OWASP = ("LLM06",)

COMMAND_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "recursive-delete-root",
        "recursive delete of /, ~, $HOME or a drive root",
        ci(
            r"\brm\s+(?:-{1,2}[a-z\-]{1,20}\s+){0,4}-[a-z]{0,5}r[a-z]{0,5}\s+"
            r"(?:-{1,2}[a-z\-]{1,20}\s+){0,4}(?:/\*?|~/?\*?|\$home/?|\"?\$\{?home\}?\"?/?|\*)"
            r"(?:\s|$|;|&|\|)|"
            r"\b(?:remove-item|rd|rmdir|del)\b[^\n;|&]{0,80}?\s(?:[a-z]:\\\\?\*?|\$env:userprofile|~)"
            r"(?:\s|$)[^\n;|&]{0,80}?-recurse|\bformat\s+[a-z]:\s"
        ),
        Severity.CRITICAL,
        ("rm", "remove-item", "rd", "rmdir", "del", "format"),
        ("AML.T0101", "T1485"),
        _OWASP,
    ),
    PatternRule(
        "destructive-disk-or-tree",
        "find -delete or -exec rm from /, ~ or $HOME, or a raw write or format of a disk",
        ci(
            r"\bfind\s+(?:/|~/?|\$home/?|\"?\$\{?home\}?\"?/?)(?=\s|$)[^\n;|&]{0,200}?"
            r"\s-(?:delete\b|exec(?:dir)?\s+rm\b)|"
            r"\bdd\b[^\n;|&]{0,200}?\bof=/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|"
            r"mmcblk\d|disk\d|rdisk\d|mapper/)|"
            r"\b(?:mkfs(?:\.[a-z0-9]{1,10})?|mke2fs|wipefs|shred)\b[^\n;|&]{0,100}?\s/dev/"
            r"(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|disk\d|rdisk\d|mapper/)|"
            r"\b(?:clear-disk|format-volume|initialize-disk)\b"
        ),
        Severity.CRITICAL,
        ("find", "dd", "mkfs", "mke2fs", "wipefs", "shred", "-disk", "-volume"),
        ("AML.T0101", "T1485", "T1561"),
        _OWASP,
    ),
    PatternRule(
        "download-and-execute",
        "downloads a script and pipes it to a shell",
        ci(
            r"\b(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|;]{0,300}"
            r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|"
            r"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n;]{0,300}\|\s*(?:iex|invoke-expression)\b|"
            r"\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*(?:new-object\s+net\.webclient|iwr|irm)"
        ),
        Severity.CRITICAL,
        ("curl", "wget", "fetch", "iwr", "irm", "invoke-", "iex"),
        ("AML.T0053", "T1105", "T1059"),
        _OWASP,
    ),
    PatternRule(
        "encoded-powershell",
        "PowerShell with an encoded command",
        ci(
            r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}?\s-e(?:c|nc|ncodedcommand)?\s+"
            r"[a-z0-9+/=]{16,}"
        ),
        Severity.HIGH,
        ("powershell", "pwsh"),
        ("AML.T0053", "T1059.001", "T1027"),
        _OWASP,
    ),
    PatternRule(
        "reverse-shell",
        "reverse shell",
        ci(
            r"/dev/(?:tcp|udp)/[a-z0-9.\-]{1,255}/\d{1,5}|"
            r"\b(?:nc|ncat|netcat)\b[^\n]{0,100}?\s-(?:e|c)\s+(?:/bin/)?(?:ba)?sh\b|"
            r"\bsocket\.socket\([^\n]{0,200}?\bsubprocess\b|"
            r"\bmkfifo\b[^\n]{0,100}?\b(?:nc|ncat)\b"
        ),
        Severity.CRITICAL,
        ("/dev/tcp", "/dev/udp", "nc", "netcat", "socket", "mkfifo"),
        ("AML.T0053", "T1059.004"),
        _OWASP,
    ),
    PatternRule(
        "environment-exfiltration",
        "environment or credentials piped to a network tool",
        ci(
            r"\b(?:env|printenv|set|export\s+-p|get-childitem\s+env:|gci\s+env:|"
            r"cat\s+[^\n|]{0,100}(?:\.env|credentials|id_rsa|\.npmrc|\.pypirc))\s*\|\s*"
            r"(?:curl|wget|nc|ncat|netcat|invoke-webrequest|iwr)\b"
        ),
        Severity.HIGH,
        ("|",),
        ("AML.T0086", "T1048"),
        ("LLM02", "LLM06"),
    ),
    PatternRule(
        "defense-evasion",
        "disables security tooling or destroys recovery data",
        ci(
            r"\bset-mppreference\b[^\n]{0,100}?-disable\w{0,40}|"
            r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|"
            r"\bwmic\s+shadowcopy\s+delete\b|"
            r"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|"
            r"\bbcdedit\b[^\n]{0,60}?recoveryenabled\s+no\b|"
            r"\b(?:setenforce\s+0|ufw\s+disable|systemctl\s+(?:stop|disable)\s+(?:auditd|apparmor))\b|"
            r"\bhistory\s+-c\b"
        ),
        Severity.HIGH,
        (
            "mppreference",
            "vssadmin",
            "shadowcopy",
            "wevtutil",
            "bcdedit",
            "setenforce",
            "ufw",
            "systemctl",
            "history",
        ),
        ("AML.T0053", "T1562.001", "T1490"),
        _OWASP,
    ),
)


def detect_commands(strings: Iterable[tuple[str, str]]) -> list[Finding]:
    return scan(DETECTOR_ID, strings, COMMAND_RULES)
