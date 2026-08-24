"""Bounded asynchronous next-strategy preparation for projected sessions."""

from __future__ import annotations

import json
import logging
import math
import queue
import threading
import time
from typing import Any, Callable
from urllib.request import Request, urlopen

ADAPTATION_VERSION = "async-adaptation-v1"
_MAX_RESPONSE_BYTES = 16_384
_SENTINEL = object()

logger = logging.getLogger(__name__)


class AsyncStrategyAdapter:
    """Keep strategy-agent I/O off Redpanda and attacker query threads."""

    def __init__(
        self,
        state_store,
        endpoint: str,
        operator_mode: str = "RULE_ADAPTIVE",
        timeout_seconds: float = 0.5,
        queue_size: int = 2048,
        request_fn: Callable[[dict, float], dict] | None = None,
        autostart: bool = True,
    ):
        self.state_store = state_store
        self.endpoint = str(endpoint or "").strip()
        self.operator_mode = str(operator_mode or "STATIC").strip().upper()
        self.timeout_seconds = min(max(float(timeout_seconds), 0.05), 5.0)
        self._queue: queue.Queue = queue.Queue(maxsize=min(max(int(queue_size), 1), 100_000))
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._request_fn = request_fn or self._request
        self._stopped = threading.Event()
        self._thread = threading.Thread(
            target=self._worker, name="strategy-adaptation", daemon=True
        )
        self._stats = {
            "scheduled": 0, "coalesced": 0, "dropped": 0,
            "completed": 0, "failed": 0, "stale": 0,
        }
        if autostart:
            self.start()

    def start(self) -> None:
        if not self._thread.is_alive() and not self._stopped.is_set():
            self._thread.start()

    def schedule(self, session_id: Any) -> bool:
        session_id = str(session_id or "").strip()[:256]
        if not session_id or self._stopped.is_set():
            return False
        with self._lock:
            if session_id in self._pending:
                self._stats["coalesced"] += 1
                return True
            self._pending.add(session_id)
        try:
            self._queue.put_nowait(session_id)
        except queue.Full:
            with self._lock:
                self._pending.discard(session_id)
                self._stats["dropped"] += 1
            return False
        with self._lock:
            self._stats["scheduled"] += 1
        return True

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _SENTINEL:
                    return
                session_id = str(item)
                with self._lock:
                    self._pending.discard(session_id)
                self._process(session_id)
            finally:
                self._queue.task_done()

    def _process(self, session_id: str) -> None:
        snapshot = self.state_store.get_adaptation_snapshot(session_id)
        if not snapshot:
            return
        self.state_store.observe_strategy_outcomes(snapshot)
        if snapshot.get("closed"):
            return
        payload = {
            "session_state": snapshot["session_state"],
            "behavior_state": snapshot["behavior_state"],
            "mitre_state": snapshot["mitre_state"],
            "operator_mode": self.operator_mode,
        }
        try:
            wall_started = time.perf_counter()
            cpu_started = time.process_time()
            decision = self._request_fn(payload, self.timeout_seconds)
            latency_ms = (time.perf_counter() - wall_started) * 1000.0
            cpu_cost_ms = (time.process_time() - cpu_started) * 1000.0
            if not isinstance(decision, dict):
                raise ValueError("strategy response must be an object")
            applied = self.state_store.set_next_strategy(
                session_id, decision, snapshot["query_count"]
            )
            if applied:
                memory_cost_bytes = len(json.dumps(
                    payload, separators=(",", ":"), sort_keys=True
                ).encode("utf-8")) + len(json.dumps(
                    decision, separators=(",", ":"), sort_keys=True
                ).encode("utf-8"))
                recorded = self.state_store.record_strategy_decision(
                    snapshot,
                    decision,
                    latency_ms=latency_ms,
                    cpu_cost_ms=cpu_cost_ms,
                    memory_cost_bytes=memory_cost_bytes,
                )
                if recorded is None:
                    raise ValueError("accepted decision telemetry was rejected")
                latest = self.state_store.get_adaptation_snapshot(session_id)
                if latest:
                    self.state_store.observe_strategy_outcomes(latest)
            with self._lock:
                self._stats["completed" if applied else "stale"] += 1
        except Exception as exc:
            with self._lock:
                self._stats["failed"] += 1
            logger.warning(
                "Asynchronous strategy update failed: session=%s error=%s",
                session_id[:8], type(exc).__name__,
            )

    def _request(self, payload: dict, timeout_seconds: float) -> dict:
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(encoded) > 131_072:
            raise ValueError("strategy request too large")
        request = Request(
            self.endpoint,
            data=encoded,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ValueError("strategy response too large")
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("strategy response must be an object")
        confidence = parsed.get("confidence")
        if not isinstance(confidence, (int, float)) or not math.isfinite(float(confidence)):
            raise ValueError("invalid strategy confidence")
        return parsed

    def stats(self) -> dict[str, Any]:
        with self._lock:
            payload = dict(self._stats)
            payload["pending"] = len(self._pending)
        payload.update({
            "version": ADAPTATION_VERSION,
            "operator_mode": self.operator_mode,
            "worker_alive": self._thread.is_alive(),
            "queue_depth": self._queue.qsize(),
        })
        return payload

    def stop(self, timeout: float = 2.0) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        try:
            self._queue.put(_SENTINEL, timeout=1.0)
        except queue.Full:
            return
        if self._thread.is_alive():
            self._thread.join(timeout=max(0.0, timeout))
