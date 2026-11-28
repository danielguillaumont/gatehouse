"""Runs one classifier under its latency budget (ADR-0007)."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import anyio

from gatehouse.classify.backends import BackendError, build_backend
from gatehouse.classify.base import Backend, Verdict, chunks
from gatehouse.policy.models import ClassifierSettings, ClassifierSurface


@dataclass
class ClassifierRunner:
    settings: ClassifierSettings
    backend: Backend | None
    build_error: str | None = None

    @classmethod
    def from_settings(cls, settings: ClassifierSettings) -> ClassifierRunner:
        try:
            return cls(settings, build_backend(settings))
        except BackendError as exc:
            return cls(settings, None, str(exc))

    def applies_to(self, surface: ClassifierSurface) -> bool:
        return surface in self.settings.applies_to

    async def classify(self, value: Any, root: str) -> Verdict:
        """A verdict within the budget, or a verdict with no score. Never raises."""
        texts, truncated = chunks(value, root)
        started = time.monotonic()

        def elapsed() -> float:
            return round((time.monotonic() - started) * 1000.0, 1)

        if not texts:
            return Verdict(0.0, 0.0, 0, truncated)
        if self.backend is None:
            return Verdict(None, 0.0, len(texts), truncated, self.build_error or "unavailable")
        budget = self.settings.budget_ms / 1000.0
        try:
            with anyio.fail_after(budget):
                scores = await self.backend.scores(texts, timeout=budget)
        except TimeoutError:
            return Verdict(None, elapsed(), len(texts), truncated, "timeout")
        except BackendError as exc:
            return Verdict(None, elapsed(), len(texts), truncated, str(exc)[:120])
        except Exception as exc:  # a backend bug must not take the proxy down
            return Verdict(None, elapsed(), len(texts), truncated, type(exc).__name__)
        if len(scores) != len(texts) or not all(0.0 <= s <= 1.0 for s in scores):
            return Verdict(None, elapsed(), len(texts), truncated, "invalid scores")
        return Verdict(max(scores), elapsed(), len(texts), truncated)
