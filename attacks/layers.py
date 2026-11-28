"""Layer combinations for the ablation table (M6, D-048).

Each entry is an overlay merged into the scenario's policy (``attacks/policy-eval.yaml``,
or ``attacks/policy-flow.yaml`` for the flow.* chains) and into the benchmark policy:

- ``observe``: everything off except logging. Detectors still run and record findings,
  but nothing is blocked.
- ``pinning``: trust-on-first-use pinning only.
- ``detectors``: content detectors enforce (block high and critical), no pinning.
- ``v0.1``: detectors and pinning, no flow control. That's v0.1's protection.
- ``structural``: pinning and flow control (approve), with the content detectors only
  logging. That's what is left if every content rule is evaded.
- ``full``: detectors, pinning and flow control (approve). This is the default for
  ``flow.*`` scenarios, and adds flow control to the eval policy.
- ``judge``: ``full`` plus a local LLM judge (Ollama) that must clear every tool
  result (``enforce``). Runs only where Ollama is installed (the CI job does that).

Response controls (quarantine, the circuit breaker) stay at their defaults in every
row. They act on findings, so a row whose detectors only log never triggers them.
"""

from __future__ import annotations

import json
from typing import Any, cast

import yaml

_LOG_ONLY = {
    "critical": "log",
    "high": "log",
    "medium": "log",
    "low": "log",
    "informational": "log",
}
_ENFORCE = {
    "critical": "block",
    "high": "block",
    "medium": "log",
    "low": "log",
    "informational": "log",
}

# The judge layer: ``full`` plus a local LLM judge in enforce mode on tool results
# (ADR-0007). Qwen2.5 1.5B Instruct is Apache-2.0 and runs on a CPU runner. The
# budget is generous because CI has no GPU; the latency table says what it costs.
JUDGE_MODEL = "qwen2.5:1.5b"
_JUDGE: dict[str, Any] = {
    "id": "judge",
    "kind": "ollama",
    "model": JUDGE_MODEL,
    "mode": "enforce",
    "applies_to": ["results"],
    "budget_ms": 60000,
}

LAYERS: dict[str, dict[str, Any]] = {
    "observe": {"pinning": "off", "findings": _LOG_ONLY, "flow": {"mode": "off"}},
    "pinning": {"pinning": "tofu", "findings": _LOG_ONLY, "flow": {"mode": "off"}},
    "detectors": {"pinning": "off", "findings": _ENFORCE, "flow": {"mode": "off"}},
    "v0.1": {"pinning": "tofu", "findings": _ENFORCE, "flow": {"mode": "off"}},
    "structural": {"pinning": "tofu", "findings": _LOG_ONLY, "flow": {"mode": "approve"}},
    "full": {"pinning": "tofu", "findings": _ENFORCE, "flow": {"mode": "approve"}},
    "judge": {
        "pinning": "tofu",
        "findings": _ENFORCE,
        "flow": {"mode": "approve"},
        "classifiers": [_JUDGE],
    },
}
# Layers that need more than the repo: the judge needs a local Ollama with JUDGE_MODEL.
NEEDS_OLLAMA = frozenset({"judge"})


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overlay.items():
        current = out.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            out[key] = _merge(cast(dict[str, Any], current), cast(dict[str, Any], value))
        else:
            out[key] = value
    return out


def apply(policy_text: str, layer: str | None) -> str:
    """The policy text with the layer's overlay merged in (unchanged for ``None``)."""
    if layer is None:
        return policy_text
    if layer not in LAYERS:
        raise ValueError(f"unknown layer combination {layer!r}; one of {sorted(LAYERS)}")
    base = cast(dict[str, Any], yaml.safe_load(policy_text))
    # JSON is YAML, and json.dumps is deterministic and fully typed.
    return json.dumps(_merge(base, LAYERS[layer]), indent=1) + "\n"
