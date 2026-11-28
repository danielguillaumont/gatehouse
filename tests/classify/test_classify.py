"""Model-based detectors: budgets, fail-closed/open per mode, backends (ADR-0007)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import anyio
import pytest

from gatehouse.classify import backends
from gatehouse.classify.backends import BackendError, OllamaJudge, PromptGuard, PromptShields
from gatehouse.classify.base import (
    CHUNK_CHARS,
    MAX_CHUNKS,
    UNAVAILABLE_RULE,
    Verdict,
    chunks,
    definition_text,
    findings_for,
)
from gatehouse.classify.runner import ClassifierRunner
from gatehouse.events.schema import Severity
from gatehouse.policy.errors import PolicyError
from gatehouse.policy.loader import parse_policy
from gatehouse.policy.models import ClassifierSettings
from tests.helpers import make_harness

# Benign-looking test text: the fake backends decide, not the content.
FLAG = "SYNTHETIC-CLASSIFIER-TRIGGER"


class Fake:
    """Scores 0.99 for text containing FLAG, else 0.01; optionally slow or broken."""

    def __init__(self, delay: float = 0.0, error: Exception | None = None) -> None:
        self.delay = delay
        self.error = error
        self.seen: list[list[str]] = []

    async def scores(self, texts: list[str], timeout: float) -> list[float]:
        self.seen.append(texts)
        if self.delay:
            await anyio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        return [0.99 if FLAG in t else 0.01 for t in texts]


def _settings(**kw: Any) -> ClassifierSettings:
    base: dict[str, Any] = {"id": "judge", "kind": "ollama", "model": "m", "mode": "enforce"}
    return ClassifierSettings.model_validate({**base, **kw})


# --------------------------------------------------------------------------- pure parts


def test_chunks_are_bounded_and_report_truncation() -> None:
    texts, truncated = chunks({"content": [{"type": "text", "text": "a" * 100}]}, "result")
    assert texts == ["a" * 100] and not truncated
    many, truncated = chunks("b" * (CHUNK_CHARS * (MAX_CHUNKS + 2)), "result")
    assert len(many) == MAX_CHUNKS and all(len(c) == CHUNK_CHARS for c in many)
    assert truncated
    assert chunks({"content": []}, "result") == ([], False)


def test_definition_text_keeps_only_what_a_model_reads() -> None:
    tool = {"name": "t", "description": "d", "inputSchema": {}, "annotations": {"x": 1}}
    assert definition_text(tool) == {"name": "t", "description": "d", "inputSchema": {}}


def test_findings_for_hit_miss_and_no_answer() -> None:
    s = _settings(threshold=0.8, severity="medium")
    assert findings_for(s, Verdict(0.5, 1.0, 1, False), "result") == []
    (hit,) = findings_for(s, Verdict(0.9, 1.0, 1, False), "result")
    assert (hit.detector_id, hit.rule_id, hit.severity) == (
        "classifier.judge",
        "prompt-injection",
        Severity.MEDIUM,
    )
    (none,) = findings_for(s, Verdict(None, 500.0, 1, False, "timeout"), "result")
    assert none.rule_id == UNAVAILABLE_RULE and none.severity is Severity.HIGH


# --------------------------------------------------------------------------- runner


@pytest.mark.anyio
async def test_runner_scores_within_budget() -> None:
    r = ClassifierRunner(_settings(), Fake())
    v = await r.classify({"text": f"x {FLAG}"}, "result")
    assert v.score == 0.99 and v.error is None and v.chunks == 1


@pytest.mark.anyio
async def test_runner_times_out_to_no_answer() -> None:
    r = ClassifierRunner(_settings(budget_ms=20), Fake(delay=1.0))
    v = await r.classify({"text": "x"}, "result")
    assert v.score is None and v.error == "timeout"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "error", [BackendError("model.onnx not found in model_dir"), ValueError("bug")]
)
async def test_runner_never_raises(error: Exception) -> None:
    v = await ClassifierRunner(_settings(), Fake(error=error)).classify({"t": "x"}, "result")
    assert v.score is None and v.error


@pytest.mark.anyio
async def test_runner_rejects_out_of_range_scores() -> None:
    class Bad:
        async def scores(self, texts: list[str], timeout: float) -> list[float]:
            return [1.5]

    v = await ClassifierRunner(_settings(), Bad()).classify({"t": "x"}, "result")
    assert v.score is None and v.error == "invalid scores"


@pytest.mark.anyio
async def test_runner_without_backend_reports_why() -> None:
    v = await ClassifierRunner(_settings(), None, "$KEY is not set").classify({"t": "x"}, "r")
    assert v.score is None and v.error == "$KEY is not set"


def test_missing_shields_key_is_a_build_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GATEHOUSE_CONTENT_SAFETY_KEY", raising=False)
    s = _settings(kind="prompt_shields", endpoint="https://example.invalid", model=None)
    r = ClassifierRunner.from_settings(s)
    assert r.backend is None and r.build_error == "$GATEHOUSE_CONTENT_SAFETY_KEY is not set"


# --------------------------------------------------------------------------- policy


@pytest.mark.parametrize(
    "entry",
    [
        "{id: a, kind: ollama, model: m, endpoint: 'http://10.0.0.5:11434'}",
        "{id: a, kind: ollama, model: m, endpoint: 'https://127.0.0.1:11434'}",
        "{id: a, kind: ollama, model: m, endpoint: 'http://127.0.0.1.example.com'}",
        "{id: a, kind: ollama}",
        "{id: a, kind: prompt_shields, endpoint: 'http://cs.example.invalid'}",
        "{id: a, kind: prompt_guard}",
        "{id: A, kind: prompt_guard, model_dir: m}",
        "{id: a, kind: prompt_guard, model_dir: m, applies_to: []}",
        "{id: a, kind: prompt_guard, model_dir: m, mode: block}",
    ],
)
def test_policy_rejects_bad_classifiers(entry: str) -> None:
    with pytest.raises(PolicyError):
        parse_policy(f"version: 1\ndefault_action: allow\nclassifiers: [{entry}]\n")


def test_policy_rejects_duplicate_ids() -> None:
    entry = "{id: a, kind: prompt_guard, model_dir: m}"
    with pytest.raises(PolicyError):
        parse_policy(f"version: 1\ndefault_action: allow\nclassifiers: [{entry}, {entry}]\n")


def test_policy_defaults_to_shadow() -> None:
    p = parse_policy(
        "version: 1\ndefault_action: allow\n"
        "classifiers: [{id: pg, kind: prompt_guard, model_dir: ./models/pg2}]\n"
    )
    (c,) = p.classifiers
    assert c.mode.value == "shadow" and c.budget_ms == 500 and c.threshold == 0.9


# --------------------------------------------------------------------------- backends


@pytest.mark.anyio
async def test_prompt_shields_request_and_response(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, Any] = {}

    def post(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        sent.update(url=url, body=body, headers=headers)
        return {"documentsAnalysis": [{"attackDetected": True}, {"attackDetected": False}]}

    monkeypatch.setattr(backends, "_post_json", post)
    scores = await PromptShields("https://cs.example.invalid/", "k").scores(["a", "b"], 1.0)
    assert scores == [1.0, 0.0]
    assert sent["url"] == (
        "https://cs.example.invalid/contentsafety/text:shieldPrompt?api-version=2024-09-01"
    )
    assert sent["body"] == {"userPrompt": "", "documents": ["a", "b"]}
    assert sent["headers"] == {"Ocp-Apim-Subscription-Key": "k"}


@pytest.mark.anyio
async def test_prompt_shields_rejects_a_short_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    def post(*_: object) -> Any:
        return {"documentsAnalysis": []}

    monkeypatch.setattr(backends, "_post_json", post)
    with pytest.raises(BackendError):
        await PromptShields("https://cs.example.invalid", "k").scores(["a"], 1.0)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("response", "expected"),
    [('{"injection": true}', [1.0, 1.0]), ('{"injection": false}', [0.0, 0.0])],
)
async def test_ollama_judge(
    monkeypatch: pytest.MonkeyPatch, response: str, expected: list[float]
) -> None:
    sent: dict[str, Any] = {}

    def post(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float) -> Any:
        sent.update(url=url, body=body)
        return {"response": response}

    monkeypatch.setattr(backends, "_post_json", post)
    scores = await OllamaJudge("http://127.0.0.1:11434", "m").scores(["a", "b"], 1.0)
    assert scores == expected
    assert sent["url"] == "http://127.0.0.1:11434/api/generate"
    assert sent["body"]["options"]["temperature"] == 0 and sent["body"]["stream"] is False


@pytest.mark.anyio
async def test_ollama_judge_needs_a_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    def post(*_: object) -> Any:
        return {"response": "maybe"}

    monkeypatch.setattr(backends, "_post_json", post)
    with pytest.raises(BackendError):
        await OllamaJudge("http://127.0.0.1:11434", "m").scores(["a"], 1.0)


class _Encoding:
    def __init__(self, n: int) -> None:
        self.ids = [1] * n
        self.attention_mask = [1] * n


class _Tokenizer:
    def encode_batch(self, texts: list[str]) -> list[_Encoding]:
        return [_Encoding(len(t)) for t in texts]


class _Input:
    def __init__(self, name: str) -> None:
        self.name = name


class _Array:
    def __init__(self, rows: list[list[float]]) -> None:
        self.rows = rows

    def tolist(self) -> list[list[float]]:
        return self.rows


class _Session:
    """Logits [benign, malicious]: high malicious logit when the text is long."""

    def get_inputs(self) -> list[_Input]:
        return [_Input("input_ids"), _Input("attention_mask")]

    def run(self, outputs: None, feeds: dict[str, Any]) -> list[_Array]:
        mask = feeds["attention_mask"].tolist()
        return [_Array([[0.0, 8.0] if sum(row) > 3 else [8.0, 0.0] for row in mask])]


@pytest.mark.anyio
async def test_prompt_guard_softmax_and_label_order(tmp_path: Path) -> None:
    pytest.importorskip("numpy")
    (tmp_path / "config.json").write_text(
        json.dumps({"id2label": {"0": "LABEL_0", "1": "LABEL_1"}}), "utf-8"
    )
    guard = PromptGuard(str(tmp_path), session=_Session(), tokenizer=_Tokenizer())
    short, long = await guard.scores(["ab", "abcdef"], 1.0)
    assert short < 0.01 and long > 0.99
    # a model whose malicious class is index 0 is read from id2label
    (tmp_path / "config.json").write_text(
        json.dumps({"id2label": {"0": "MALICIOUS", "1": "BENIGN"}}), "utf-8"
    )
    flipped = PromptGuard(str(tmp_path), session=_Session(), tokenizer=_Tokenizer())
    short, long = await flipped.scores(["ab", "abcdef"], 1.0)
    assert short > 0.99 and long < 0.01


@pytest.mark.anyio
async def test_prompt_guard_without_model_fails_clearly(tmp_path: Path) -> None:
    with pytest.raises(BackendError):
        await PromptGuard(str(tmp_path)).scores(["a"], 1.0)


# --------------------------------------------------------------------------- router


def _policy(mode: str, surfaces: str = "[results, definitions]", budget: int = 500) -> str:
    return f"""
    version: 1
    default_action: allow
    pinning: tofu
    classifiers:
      - {{id: judge, kind: ollama, model: m, mode: {mode}, applies_to: {surfaces},
          budget_ms: {budget}}}
    """


def _verdicts(h: Any) -> list[dict[str, Any]]:
    return h.events("classifier.verdict")


@pytest.mark.anyio
async def test_enforce_withholds_a_flagged_result(tmp_path: Path) -> None:
    fake = Fake()
    h = make_harness(tmp_path, _policy("enforce", "[results]"), classifier_backends={"judge": fake})
    await h.initialize()
    await h.list_tools([{"name": "fetch", "inputSchema": {"type": "object"}}])
    ok = await h.call("fetch", {}, result_text="the weather is mild")
    assert ok["result"]["content"][0]["text"] == "the weather is mild"
    blocked = await h.call("fetch", {}, result_text=f"page text {FLAG}")
    assert "error" in blocked or blocked["result"].get("isError")
    assert FLAG not in json.dumps(blocked)
    (hit,) = [v for v in _verdicts(h) if v["RuleId"] == "prompt-injection"]
    assert hit["LatencyMs"] is not None and hit["Details"]["Mode"] == "enforce"
    assert FLAG not in json.dumps(h.sink.records)  # redact before logging


@pytest.mark.anyio
async def test_enforce_fails_closed_on_timeout(tmp_path: Path) -> None:
    fake = Fake(delay=1.0)
    policy = _policy("enforce", "[results]", budget=20)
    h = make_harness(tmp_path, policy, classifier_backends={"judge": fake})
    await h.initialize()
    await h.list_tools([{"name": "fetch", "inputSchema": {"type": "object"}}])
    reply = await h.call("fetch", {}, result_text="the weather is mild")
    assert "error" in reply or reply["result"].get("isError")
    (v,) = _verdicts(h)
    assert v["RuleId"] == UNAVAILABLE_RULE and v["Action"] == "fail_closed"


@pytest.mark.anyio
async def test_unavailable_classifier_is_not_a_circuit_breaker_strike(tmp_path: Path) -> None:
    from gatehouse.proxy import router

    assert UNAVAILABLE_RULE in router._NOT_STRIKES  # pyright: ignore[reportPrivateUsage]


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["shadow", "alert"])
async def test_shadow_and_alert_never_change_traffic(tmp_path: Path, mode: str) -> None:
    fake = Fake()
    h = make_harness(tmp_path, _policy(mode), classifier_backends={"judge": fake})
    await h.initialize()
    tools = await h.list_tools([{"name": "fetch", "description": f"d {FLAG}"}])
    assert [t["name"] for t in tools] == ["fetch"]
    reply = await h.call("fetch", {}, result_text=f"page {FLAG}")
    assert reply["result"]["content"][0]["text"] == f"page {FLAG}"
    hits = [v for v in _verdicts(h) if v["RuleId"] == "prompt-injection"]
    assert len(hits) == 2 and all(v["Details"]["Mode"] == mode for v in hits)
    detections = h.events("detection", DetectorId="classifier.judge")
    assert len(detections) == (2 if mode == "alert" else 0)
    assert all(d["Action"] == "logged" for d in detections)


@pytest.mark.anyio
async def test_shadow_timeout_fails_open_without_blocking(tmp_path: Path) -> None:
    fake = Fake(delay=1.0)
    h = make_harness(tmp_path, _policy("shadow", budget=20), classifier_backends={"judge": fake})
    await h.initialize()
    await h.list_tools([{"name": "fetch", "inputSchema": {"type": "object"}}])
    reply = await h.call("fetch", {}, result_text="hello")
    assert reply["result"]["content"][0]["text"] == "hello"
    assert all(v["Action"] == "none" and v["Severity"] == "informational" for v in _verdicts(h))


@pytest.mark.anyio
async def test_enforce_filters_a_flagged_definition_and_caches_verdicts(tmp_path: Path) -> None:
    fake = Fake()
    policy = _policy("enforce", "[definitions]")
    h = make_harness(tmp_path, policy, classifier_backends={"judge": fake})
    await h.initialize()
    tools = [
        {"name": "ok", "description": "Reads the time."},
        {"name": "bad", "description": f"Reads files. {FLAG}"},
    ]
    assert [t["name"] for t in await h.list_tools(tools)] == ["ok"]
    calls = len(fake.seen)
    assert [t["name"] for t in await h.list_tools(tools)] == ["ok"]
    assert len(fake.seen) == calls  # unchanged definitions are not re-classified
