"""The pure half of classification: inputs, verdicts and findings (ADR-0007)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from gatehouse.events.schema import Severity
from gatehouse.inspect.base import Finding
from gatehouse.inspect.walk import WalkStats, iter_strings
from gatehouse.policy.models import ClassifierMode, ClassifierSettings

# Bounds on what one verdict looks at. Prompt Guard 2 reads 512 tokens, and Prompt
# Shields takes 5 documents of 10K characters in total, so a chunk is about 2,000
# characters and at most 5 go to any backend. Text past the bound isn't classified,
# and the verdict says so (``truncated``).
CHUNK_CHARS = 2000
MAX_CHUNKS = 5

# MCP framing fields, not content: left out of what a model reads.
_STRUCTURAL = (".type", ".mimeType", ".uri", ".resultType")

UNAVAILABLE_RULE = "classifier-unavailable"
HIT_RULE = "prompt-injection"


class Backend(Protocol):
    """One model. ``scores`` returns, per text, the probability that it is an attack."""

    async def scores(self, texts: list[str], timeout: float) -> list[float]: ...


@dataclass(frozen=True)
class Verdict:
    score: float | None  # highest chunk score; None if the backend gave no answer
    latency_ms: float
    chunks: int
    truncated: bool
    error: str | None = None

    def hit(self, threshold: float) -> bool:
        return self.score is not None and self.score >= threshold


def chunks(value: Any, root: str) -> tuple[list[str], bool]:
    """The text a classifier sees: every string in ``value``, in order, cut into chunks
    of ``CHUNK_CHARS``. Returns (chunks, truncated)."""
    stats = WalkStats()
    strings = iter_strings(value, root, stats, include_keys=False)
    text = "\n".join(s for path, s in strings if not path.endswith(_STRUCTURAL))
    out = [text[i : i + CHUNK_CHARS] for i in range(0, len(text), CHUNK_CHARS)]
    out = [c for c in out if c.strip()]
    truncated = len(out) > MAX_CHUNKS or stats.truncated
    return out[:MAX_CHUNKS], truncated


def definition_text(tool: Mapping[str, Any]) -> dict[str, Any]:
    """The parts of a tool definition a model reads: name, description, schema."""
    keys = ("name", "title", "description", "inputSchema", "outputSchema")
    return {k: tool[k] for k in keys if k in tool}


def findings_for(settings: ClassifierSettings, verdict: Verdict, location: str) -> list[Finding]:
    """What an *enforce* classifier contributes to the decision (pure).

    A hit is a finding at the configured severity. No verdict (timeout, error, model
    missing) is a high finding, so enforce mode fails closed (ADR-0001)."""
    detector = f"classifier.{settings.id}"
    if verdict.score is None:
        return [
            Finding(
                detector_id=detector,
                rule_id=UNAVAILABLE_RULE,
                severity=Severity.HIGH,
                summary=f"no verdict within {settings.budget_ms} ms ({verdict.error})"[:200],
                location=location,
            )
        ]
    if not verdict.hit(settings.threshold):
        return []
    return [
        Finding(
            detector_id=detector,
            rule_id=HIT_RULE,
            severity=Severity(settings.severity.value),
            summary=(
                f"score {verdict.score:.2f} >= {settings.threshold:.2f} ({settings.kind.value})"
            ),
            location=location,
            mitre=("AML.T0051.001",),
            owasp=("LLM01",),
        )
    ]


def is_enforcing(settings: ClassifierSettings) -> bool:
    return settings.mode is ClassifierMode.ENFORCE
