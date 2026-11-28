"""Every ablation row yields a valid policy for the eval, flow and bench bases (D-048)."""

from __future__ import annotations

import pytest

from attacks.layers import LAYERS, apply
from attacks.targets import EVAL_POLICY, FLOW_POLICY
from bench.latency import policy_text
from gatehouse.policy.loader import parse_policy
from gatehouse.policy.models import FindingAction, FlowMode, PinningMode


@pytest.mark.parametrize("layer", sorted(LAYERS))
def test_layer_applies_to_every_base(layer: str) -> None:
    overlay = LAYERS[layer]
    flow_text = FLOW_POLICY.read_text(encoding="utf-8").replace("FLOW_MODE", "approve")
    for text in (EVAL_POLICY.read_text(encoding="utf-8"), flow_text, policy_text("allow", layer)):
        policy = parse_policy(apply(text, layer))
        assert policy.pinning == PinningMode(overlay["pinning"])
        assert policy.flow.mode == FlowMode(overlay["flow"]["mode"])
        assert policy.findings.high == FindingAction(overlay["findings"]["high"])


def test_flow_policy_keeps_its_servers_and_labels() -> None:
    flow_text = FLOW_POLICY.read_text(encoding="utf-8").replace("FLOW_MODE", "approve")
    policy = parse_policy(apply(flow_text, "structural"))
    assert set(policy.servers) == set(parse_policy(flow_text).servers)


def test_no_layer_means_the_policy_as_written() -> None:
    text = EVAL_POLICY.read_text(encoding="utf-8")
    assert apply(text, None) == text
