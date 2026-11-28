"""`gatehouse policy prove` (D-041): invariants, the bounded checker, symcc plumbing."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import cedarpy
import pytest

from gatehouse.cli import main
from gatehouse.policy import PolicyError, parse_policy
from gatehouse.policy.cedar import CedarEngine
from gatehouse.policy.prove import (
    bound_policy,
    bounded_check,
    parse_invariants,
    prove,
    symcc_check,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "policy-flow.yaml"
INVARIANTS = ROOT / "examples" / "invariants.yaml"
BROKEN = Path(__file__).parent / "fixtures" / "policy-flow-broken.yaml"


def _engine(text: str) -> CedarEngine:
    return CedarEngine(parse_policy(text))


def _invariants(text: str) -> Any:
    return parse_invariants(text).invariants


def test_example_policy_satisfies_its_invariants(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["policy", "prove", str(EXAMPLE), "--invariants", str(INVARIANTS)])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "5/5 invariants hold" in out


def test_broken_policy_fails_prove(capsys: pytest.CaptureFixture[str]) -> None:
    # Roadmap M5 acceptance: `policy prove` fails CI on a deliberately broken policy.
    rc = main(["policy", "prove", str(BROKEN), "--invariants", str(INVARIANTS)])
    out = capsys.readouterr().out
    assert rc == 1, out
    assert "FAILED  deletes always need a human" in out
    line = out.splitlines()[out.splitlines().index("FAILED  deletes always need a human") + 1]
    assert "delete" in line.split("tool=")[1]
    assert "FAILED  nothing leaves a session" in out


def test_require_symcc_without_cli_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def no_cli(_explicit: str | None = None) -> None:
        return None

    monkeypatch.setattr("gatehouse.policy.prove.find_cedar", no_cli)
    rc = main(["policy", "prove", str(EXAMPLE), "--invariants", str(INVARIANTS), "--require-symcc"])
    assert rc == 2
    assert "--require-symcc" in capsys.readouterr().err


_POLICY = """
version: 1
default_action: allow
servers:
  "*":
    tools:
      "*delete*": require_approval
      "rm_?": block
  fs:
    labels:
      write_file: [state_change]
"""


def test_bounded_check_finds_a_concrete_counterexample() -> None:
    engine = _engine(_POLICY)
    invs = _invariants(
        "version: 1\ninvariants:\n"
        "  - {name: deletes, tools: '*delete*', never: allow}\n"
        "  - {name: rm blocked, tools: 'rm_*', never: allow_or_approve}\n"
    )
    deletes, rm = bounded_check(engine, invs)
    assert deletes.holds is True
    assert "not a proof" in deletes.detail
    # `rm_?` blocks rm_x but not rm_xy: the bounded check builds names that just miss.
    assert rm.holds is False
    assert rm.counterexample is not None
    assert rm.counterexample.tool.startswith("rm_")
    assert len(rm.counterexample.tool) != 4


def test_bounded_check_combines_patterns() -> None:
    # SymCC found this one first (D-041): a server-specific `read_*: allow` beats a global
    # `*delete*: require_approval`, so `read_delete` is allowed.
    engine = _engine(
        "version: 1\ndefault_action: block\nservers:\n"
        "  '*': {tools: {'*delete*': require_approval}}\n"
        "  mail: {tools: {'read_*': allow}}\n"
    )
    invs = _invariants("version: 1\ninvariants:\n  - {name: d, tools: '*delete*', never: allow}\n")
    (result,) = bounded_check(engine, invs)
    assert result.holds is False
    assert result.counterexample is not None
    assert result.counterexample.server == "mail"
    assert result.counterexample.tool.startswith("read_")


def test_policy_labels_are_part_of_the_scope() -> None:
    # write_file carries state_change from the policy even when the request says nothing.
    engine = _engine(_POLICY)
    invs = _invariants(
        "version: 1\ninvariants:\n"
        "  - {name: no writes, tool_labels: [state_change], never: allow}\n"
    )
    (result,) = bounded_check(engine, invs)
    assert result.holds is False
    assert result.counterexample is not None
    assert "state_change" in result.counterexample.tool_labels


def test_pinned_tools_are_checked() -> None:
    engine = _engine("version: 1\ndefault_action: allow\n")
    invs = _invariants("version: 1\ninvariants:\n  - {name: x, tools: 'purge', never: allow}\n")
    (result,) = bounded_check(engine, invs, extra_names=[("db", "PURGE")])
    assert result.holds is False


def test_bound_policies_validate_against_the_schema() -> None:
    engine = _engine(_POLICY)
    schema = cedarpy.Schema.from_json_str(__import__("json").dumps(engine.compiled.schema))
    for inv in _invariants(INVARIANTS.read_text(encoding="utf-8")):
        q = bound_policy(inv, engine.compiled)
        check: Any = cedarpy.validate_policies(q, schema)  # pyright: ignore[reportUnknownMemberType]
        assert check.validation_passed, (q, [str(e) for e in check.errors])


@pytest.mark.parametrize(
    "bad",
    [
        "version: 1\ninvariants: []\n",
        "version: 2\ninvariants:\n  - {name: a, never: allow}\n",
        "version: 1\ninvariants:\n  - {name: a, never: sometimes}\n",
        "version: 1\ninvariants:\n  - {name: a, tools: 'rm_?', never: allow}\n",
        "version: 1\ninvariants:\n  - {name: a, never: allow, typo: 1}\n",
        "version: 1\ninvariants:\n  - {name: a, never: allow}\n  - {name: a, never: allow}\n"
        "invariants: []\n",
    ],
)
def test_invalid_invariant_files(bad: str) -> None:
    with pytest.raises(PolicyError):
        parse_invariants(bad)


# --- symcc plumbing (the CLI itself runs in the policy-prove CI job) -----------------------


def _fake_run(stdout: str, stderr: str = "", rc: int = 0) -> Any:
    def run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        assert cmd[1] == "symcc"
        assert "implies" in cmd
        return subprocess.CompletedProcess(cmd, rc, stdout.encode(), stderr.encode())

    return run


_INV = "version: 1\ninvariants:\n  - {name: d, tools: '*delete*', never: allow}\n"


def test_symcc_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", _fake_run("✓ Policy set 1 implies policy set 2: VERIFIED\n")
    )
    (r,) = symcc_check("cedar", _engine(_POLICY), _invariants(_INV))
    assert r.holds is True
    assert r.prover == "symcc"


def test_symcc_does_not_hold_with_exit_code_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    # The CLI exits 0 when a property fails; only its output says so.
    out = (
        "✗ Policy set 1 implies policy set 2: DOES NOT HOLD\n"
        "  Counterexample found:\n  request: ...\n"
    )
    monkeypatch.setattr(subprocess, "run", _fake_run(out, rc=0))
    (r,) = symcc_check("cedar", _engine(_POLICY), _invariants(_INV))
    assert r.holds is False
    assert "Counterexample" in r.detail
    assert r.maybe_spurious  # the policy uses `rm_?`, which symcc sees as a free group


def test_symcc_error_is_not_a_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    err = "  × Analysis failed\n  ├─▶ CVC5 solver not found or failed to start\n"
    monkeypatch.setattr(subprocess, "run", _fake_run("", err, rc=1))
    (r,) = symcc_check("cedar", _engine(_POLICY), _invariants(_INV))
    assert r.holds is None
    assert "CVC5 solver not found" in r.detail
    assert r.detail.isascii()


def test_bounded_counterexample_wins_over_symcc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", _fake_run("✓ Policy set 1 implies policy set 2: VERIFIED\n")
    )
    engine = _engine("version: 1\ndefault_action: allow\n")
    (r,) = prove(engine, _invariants(_INV), cedar="cedar")
    assert r.holds is False  # a real, concrete counterexample is never overridden
    assert r.counterexample is not None


def test_compile_writes_policy_schema_and_pinned_entities(tmp_path: Path) -> None:
    from gatehouse.state.pinstore import pin_tools

    pins = tmp_path / "pins.json"
    pin_tools(
        pins,
        "mail",
        {"send_email": {"name": "send_email", "inputSchema": {"type": "object"}}},
        pinned_by="pin",
    )
    out = tmp_path / "out"
    rc = main(["policy", "compile", str(EXAMPLE), "--out", str(out), "--pins", str(pins)])
    assert rc == 0
    assert (out / "policy.cedar").read_text(encoding="utf-8").startswith("@id(")
    entities = __import__("json").loads((out / "entities.json").read_text(encoding="utf-8"))
    assert entities[0]["uid"]["id"] == "mail/send_email"
    assert entities[0]["attrs"]["labels"] == ["egress"]
