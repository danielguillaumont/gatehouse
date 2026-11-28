"""Held-out v2 is frozen (D-046): any change to its seeds, generator, model rewrites or
output fails here. Updating MANIFEST.json is only legitimate together with new seeds
(held-out v3), never to absorb a detector change."""

from __future__ import annotations

import json
from collections import Counter

from attacks.harness import load_scenarios
from attacks.heldout2 import mutate


def test_frozen_files_match_the_manifest() -> None:
    assert mutate.frozen_mismatches() == []


def test_generator_reproduces_the_frozen_output() -> None:
    frozen = mutate.OUT.read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
    assert mutate.render(mutate.generate()) == frozen


def test_scenarios_load_and_match_the_recorded_counts() -> None:
    scenarios = load_scenarios(mutate.SCENARIOS)
    counts = json.loads(mutate.MANIFEST.read_text(encoding="utf-8"))["counts"]
    attacks = [s for s in scenarios if not s.benign]
    assert len(attacks) == counts["attacks"]
    assert len(scenarios) - len(attacks) == counts["benign"]
    assert {s.milestone for s in scenarios} == {"m6"}
    by_op = Counter(s.id.rsplit(".", 1)[1] for s in attacks)
    assert dict(sorted(by_op.items())) == counts["attacks_by_operator"]


def test_held_out_v2_is_not_in_the_main_suite() -> None:
    assert not [s for s in load_scenarios() if s.milestone == "m6"]


def test_meaning_preserving_operators_keep_the_marker() -> None:
    llm = mutate.load_llm()
    for seed in mutate.load_seeds():
        if seed.marker is None:
            continue
        for v in mutate.variants(seed, llm):
            if v.needle is None:
                assert seed.marker in v.text, (seed.id, v.op)
