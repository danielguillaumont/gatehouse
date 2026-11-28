"""gatehouse status / kill / unlock / review / grant."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatehouse.cli import main
from gatehouse.control_cli import duration, reveal
from gatehouse.state.control import CONTROL_DB, ControlStore


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ControlStore:
    monkeypatch.setenv("GATEHOUSE_HOME", str(tmp_path))
    return ControlStore(tmp_path / CONTROL_DB)


def test_kill_and_release(store: ControlStore, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["kill", "--reason", "incident 7"]) == 0
    state = store.kill_state()
    assert state is not None and state.reason == "incident 7"
    assert main(["status"]) == 0
    assert "ENGAGED (incident 7)" in capsys.readouterr().out
    assert main(["kill", "--off"]) == 0
    assert store.kill_state() is None


def test_review_show_reveals_hidden_text_and_release(
    store: ControlStore, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = {"content": [{"type": "text", "text": "hello​ world\U000e0041"}]}
    qid = store.quarantine(
        session="s",
        server="web",
        tool="get_page",
        call_key="k",
        summary="response.injection/x",
        payload=json.dumps(payload).encode(),
    )
    assert main(["review"]) == 0
    assert qid in capsys.readouterr().out
    assert main(["review", "show", qid]) == 0
    out = capsys.readouterr().out
    assert "hello⟦U+200B⟧ world⟦U+E0041⟧" in out
    assert main(["review", "release", qid]) == 0
    assert store.take_released("s", "web", "k") is not None
    assert main(["review", "release", qid]) == 1  # already delivered


def test_grant_add_list_revoke(store: ControlStore, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        [
            "grant",
            "add",
            "mail",
            "send_email",
            "--when",
            "{to: {email_domains: [mycorp.com]}}",
            "--for",
            "30m",
            "--uses",
            "3",
        ]
    )
    assert rc == 0
    (g,) = store.grants()
    assert g.conditions == {"to": {"email_domains": ["mycorp.com"]}}
    assert g.uses_left == 3
    assert 1790 < g.expires - g.created <= 1800
    assert main(["grant", "revoke", g.id]) == 0
    assert store.grants() == []


@pytest.mark.parametrize(
    "when", ["{to: {email_domain: [x.com]}}", "[1, 2]", "{to: {url_hosts: ['*']}}"]
)
def test_bad_grant_conditions_are_refused(store: ControlStore, when: str) -> None:
    assert main(["grant", "add", "mail", "send_email", "--when", when]) == 2
    assert store.grants() == []


def test_unlock_needs_a_session_when_several_are_locked(store: ControlStore) -> None:
    store.lock("a", "x")
    store.lock("b", "y")
    assert main(["unlock"]) == 2
    assert main(["unlock", "--session", "a"]) == 0
    assert main(["unlock"]) == 0  # one left: unlocked without naming it
    assert store.locks() == []


@pytest.mark.parametrize(("text", "seconds"), [("90s", 90), ("30m", 1800), ("2d", 172800)])
def test_duration(text: str, seconds: int) -> None:
    assert duration(text) == seconds


@pytest.mark.parametrize("text", ["0m", "8d", "30", "m", "1.5h", "-3m"])
def test_bad_duration(text: str) -> None:
    with pytest.raises(ValueError):
        duration(text)


def test_reveal_keeps_newlines_and_tabs() -> None:
    assert reveal("a\nb\tc‮d") == "a\nb\tc⟦U+202E⟧d"
