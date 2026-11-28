"""Egress destinations in events: registrable domains only (D-057)."""

from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.inspect.egress import MAX_DOMAINS, egress_domains, registrable
from tests.helpers import make_harness, tool_def


@pytest.mark.parametrize(
    ("host", "want"),
    [
        ("mail.evil.example", "evil.example"),
        ("EVIL.example.", "evil.example"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("files.example.com.au", "example.com.au"),
        ("10.0.0.7", "10.0.0.7"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("localhost", None),
        ("bad_label.example", None),
    ],
)
def test_registrable(host: str, want: str | None) -> None:
    assert registrable(host) == want


def test_domains_from_urls_and_emails_without_paths_or_local_parts() -> None:
    args = {
        "url": "https://user:pw@CANARY-SECRET-1.exfil.example/collect?d=CANARY-SECRET-2",
        "to": "partners@contoso-advisors.example",
        "cc": ["a@mail.contoso-advisors.example"],
        "body": "see http://10.1.2.3:8080/x and ftp://files.example.co.uk/a",
    }
    domains = egress_domains(args)
    assert domains == ("exfil.example", "contoso-advisors.example", "10.1.2.3", "example.co.uk")
    assert "CANARY" not in " ".join(domains)  # a secret in a subdomain never reaches events


def test_bounded() -> None:
    args = {"x": " ".join(f"https://h{i}.d{i}.example/" for i in range(100))}
    assert len(egress_domains(args)) == MAX_DOMAINS
    assert egress_domains({"x": "https://" + "a" * 100_000}) == ()
    assert egress_domains(None) == ()


@pytest.mark.anyio
async def test_egress_tool_calls_carry_domains(tmp_path: Path) -> None:
    h = make_harness(tmp_path, "version: 1\ndefault_action: allow\npinning: 'off'\n")
    await h.initialize()
    await h.list_tools([tool_def("send_email"), tool_def("read_note")])
    await h.call("send_email", {"to": "boss@corp.example"})
    await h.call("read_note", {"title": "https://wiki.corp.example/x"})
    calls = h.events("tool.call")
    assert calls[0]["Details"]["EgressDomains"] == ["corp.example"]
    assert "EgressDomains" not in calls[1]["Details"]  # not an egress tool
