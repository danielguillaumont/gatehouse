"""Microsoft Sentinel sink: Azure Monitor Logs Ingestion API (DCR-based custom table).

Events go to ``GatehouseEvents_CL`` through a data collection rule (DCR). The Bicep in
``infra/`` creates the table, the endpoint and the rule; ``docs/sentinel-setup.md``
explains the setup.

The proxy must never wait on the network, so ``write`` only enqueues. A daemon thread
batches records (up to ``BATCH_MAX`` or ``FLUSH_INTERVAL_S``) and uploads them. When
uploads fail after retries, or the queue is full, the *next* ``write`` raises
``SentinelSinkError``. The emitter turns that into a ``gatehouse.fail_open`` event on
the sinks that still work (telemetry loss is the one fail-open path, ADR-0001), so the
gap is visible in the local JSONL log.

Needs the ``sentinel`` extra: ``pip install "gatehouse[sentinel]"``. Authentication is
``DefaultAzureCredential`` (managed identity, Azure CLI login, environment variables,
...); gatehouse never handles a secret for it.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_STREAM = "Custom-GatehouseEvents_CL"
ENV_ENDPOINT = "GATEHOUSE_SENTINEL_ENDPOINT"
ENV_RULE_ID = "GATEHOUSE_SENTINEL_DCR_ID"
ENV_STREAM = "GATEHOUSE_SENTINEL_STREAM"

QUEUE_MAX = 10_000
BATCH_MAX = 500
FLUSH_INTERVAL_S = 5.0
RETRIES = 3
CLOSE_TIMEOUT_S = 10.0

Uploader = Callable[[list[dict[str, Any]]], None]


class SentinelSinkError(Exception):
    """Events were lost (upload failure or back-pressure)."""


@dataclass(frozen=True)
class SentinelConfig:
    endpoint: str  # DCE (or DCR) logs ingestion endpoint, https://...ingest.monitor.azure.com
    rule_id: str  # DCR immutable id, dcr-...
    stream: str = DEFAULT_STREAM

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> SentinelConfig | None:
        env = os.environ if env is None else env
        endpoint, rule_id = env.get(ENV_ENDPOINT), env.get(ENV_RULE_ID)
        if not endpoint or not rule_id:
            return None
        return cls(endpoint, rule_id, env.get(ENV_STREAM) or DEFAULT_STREAM)


def azure_uploader(cfg: SentinelConfig) -> Uploader:
    """Uploader backed by ``azure-monitor-ingestion``. Raises ImportError without the
    ``sentinel`` extra."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient

    client = LogsIngestionClient(endpoint=cfg.endpoint, credential=DefaultAzureCredential())

    def upload(batch: list[dict[str, Any]]) -> None:
        # The SDK splits the batch into <=1 MB gzip chunks and raises on failure.
        client.upload(rule_id=cfg.rule_id, stream_name=cfg.stream, logs=list(batch))

    return upload


class SentinelSink:
    def __init__(
        self,
        uploader: Uploader,
        *,
        batch_max: int = BATCH_MAX,
        flush_interval: float = FLUSH_INTERVAL_S,
        retries: int = RETRIES,
        backoff: float = 1.0,
        queue_max: int = QUEUE_MAX,
    ) -> None:
        self._upload = uploader
        self._batch_max = batch_max
        self._interval = flush_interval
        self._retries = retries
        self._backoff = backoff
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=queue_max)
        self._lock = threading.Lock()
        self._error: str | None = None
        self.uploaded = 0
        self.dropped = 0
        self._closed = False
        self._thread = threading.Thread(target=self._run, name="gatehouse-sentinel", daemon=True)
        self._thread.start()

    # -- Sink protocol ---------------------------------------------------------------

    def write(self, record: dict[str, Any]) -> None:
        with self._lock:
            error, self._error = self._error, None
        if error is not None:
            # report the earlier loss; this record is still queued below
            self._enqueue(record)
            raise SentinelSinkError(error)
        self._enqueue(record)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._queue.put(None, timeout=1.0)
        except queue.Full:
            pass
        self._thread.join(CLOSE_TIMEOUT_S)

    # -- internals -------------------------------------------------------------------

    def _enqueue(self, record: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self._lost(1, "queue full (Sentinel ingestion can't keep up)")
            raise SentinelSinkError("Sentinel queue full; event dropped") from None

    def _lost(self, n: int, why: str) -> None:
        with self._lock:
            self.dropped += n
            self._error = f"{n} event(s) not sent to Sentinel: {why}"

    def _run(self) -> None:
        batch: list[dict[str, Any]] = []
        deadline = time.monotonic() + self._interval
        while True:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                item = self._queue.get(timeout=timeout)
            except queue.Empty:
                pass  # interval elapsed: flush what we have
            else:
                if item is None:  # close()
                    self._flush(batch)
                    return
                batch.append(item)
            if len(batch) >= self._batch_max or time.monotonic() >= deadline:
                self._flush(batch)
                batch = []
                deadline = time.monotonic() + self._interval

    def _flush(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        last = ""
        for attempt in range(self._retries):
            try:
                self._upload(batch)
            except Exception as exc:  # network, auth, 4xx/5xx: retry, then report
                last = f"{type(exc).__name__}: {str(exc)[:200]}"
                time.sleep(self._backoff * (2**attempt))
                continue
            with self._lock:
                self.uploaded += len(batch)
            return
        self._lost(len(batch), f"upload failed after {self._retries} attempts ({last})")
