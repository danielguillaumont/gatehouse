"""Personal data in tool arguments: payment cards, US SSNs, IBANs, bulk email lists.

Matches are validated (Luhn for cards, mod-97 for IBANs, SSA rules for SSNs) to keep
false positives on order numbers and IDs low. Summaries never contain the value: PII is
reported by type and location only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.rules import PatternRule, scan

DETECTOR_ID = "args.pii"
_MITRE = ("AML.T0086",)
_OWASP = ("LLM02",)


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _isolated(m: re.Match[str], chars: str) -> bool:
    """The character before the match is not one of ``chars`` (a lookbehind at the start
    of the pattern would be evaluated at every position: ~7x slower on large text)."""
    i = m.start()
    return i == 0 or m.string[i - 1] not in chars


def _card(m: re.Match[str]) -> bool:
    if not _isolated(m, "0123456789-"):
        return False
    digits = re.sub(r"\D", "", m.group(0))
    return 13 <= len(digits) <= 19 and luhn_ok(digits) and len(set(digits)) > 1


def iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    number = "".join(str(int(ch, 36)) for ch in moved)
    return int(number) % 97 == 1


def _ssn(m: re.Match[str]) -> bool:
    if not _isolated(m, "0123456789-"):
        return False
    area, group, serial = m.group(1), m.group(2), m.group(3)
    return (
        area not in ("000", "666")
        and not area.startswith("9")
        and group != "00"
        and serial != "0000"
    )


_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_DIGIT = re.compile(r"[0-9]")

PII_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "payment-card",
        "payment card number (Luhn-valid)",
        re.compile(r"\d(?:[ \-]?\d){12,18}(?![\d\-])"),
        Severity.HIGH,
        (),
        _MITRE,
        _OWASP,
        validate=_card,
    ),
    PatternRule(
        "us-ssn",
        "US Social Security number",
        re.compile(r"(\d{3})-(\d{2})-(\d{4})(?![\d\-])"),
        Severity.HIGH,
        ("-",),
        _MITRE,
        _OWASP,
        validate=_ssn,
    ),
    PatternRule(
        "iban",
        "IBAN bank account number (checksum-valid)",
        re.compile(r"[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?(?![A-Z0-9])"),
        Severity.HIGH,
        (),
        _MITRE,
        _OWASP,
        validate=lambda m: _isolated(m, _ALNUM) and iban_ok(m.group(0)),
    ),
)

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}"
)
BULK_EMAIL_THRESHOLD = 5


def detect_pii(strings: Iterable[tuple[str, str]]) -> list[Finding]:
    items = list(strings)
    # every rule needs a digit; one cheap search skips the three patterns on prose
    numeric = [(where, text) for where, text in items if _DIGIT.search(text)]
    findings = scan(DETECTOR_ID, numeric, PII_RULES, show_match=False)
    for where, text in items:
        if "@" not in text:
            continue
        emails = {m.group(0).lower() for m in _EMAIL.finditer(text)}
        if len(emails) >= BULK_EMAIL_THRESHOLD:
            findings.append(
                Finding(
                    detector_id=DETECTOR_ID,
                    rule_id="bulk-email-addresses",
                    severity=Severity.MEDIUM,
                    summary=f"{len(emails)} distinct email addresses in one argument",
                    location=where,
                    mitre=_MITRE,
                    owasp=_OWASP,
                )
            )
    return findings


# Card-network prefixes and lengths (ISO/IEC 7812 IIN ranges as the networks publish
# them). Used only for JSON numbers: integer IDs and timestamps pass Luhn 1 time in 10,
# so a bare Luhn check on every 13-19 digit number would flag ordinary order IDs.
_NETWORKS: tuple[tuple[tuple[int, int], int, tuple[int, ...]], ...] = (
    ((4, 4), 1, (13, 16, 19)),  # Visa
    ((51, 55), 2, (16,)),  # Mastercard
    ((2221, 2720), 4, (16,)),  # Mastercard 2-series
    ((34, 34), 2, (15,)),  # American Express
    ((37, 37), 2, (15,)),
    ((6011, 6011), 4, (16, 19)),  # Discover
    ((644, 649), 3, (16, 19)),
    ((65, 65), 2, (16, 19)),
    ((3528, 3589), 4, (16, 19)),  # JCB
    ((36, 36), 2, (14, 16, 19)),  # Diners Club
    ((300, 305), 3, (14, 16, 19)),
    ((62, 62), 2, (16, 17, 18, 19)),  # UnionPay
)


def card_network_ok(digits: str) -> bool:
    for (low, high), width, lengths in _NETWORKS:
        if len(digits) in lengths and low <= int(digits[:width]) <= high:
            return True
    return False


def detect_pii_numbers(numbers: Iterable[tuple[str, str]]) -> list[Finding]:
    """Card numbers sent as JSON numbers (``walk.iter_numbers``): Luhn and a network
    prefix and length must both hold."""
    return [
        Finding(
            detector_id=DETECTOR_ID,
            rule_id="payment-card",
            severity=Severity.HIGH,
            summary="payment card number (Luhn-valid, sent as a JSON number)",
            location=where,
            mitre=_MITRE,
            owasp=_OWASP,
        )
        for where, digits in numbers
        if luhn_ok(digits) and card_network_ok(digits) and len(set(digits)) > 1
    ]
