"""Bounded, no-retry client for one private Ollama CPU runtime."""

from __future__ import annotations

import hashlib
import json
import math
import socket
import threading
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from .config import CONTRACT_VERSION, LocalLLMConfig
except ImportError:
    from config import CONTRACT_VERSION, LocalLLMConfig


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class LocalLLMClient:
    """A bounded future-agent client; never used by the attacker-facing path."""

    def __init__(self, config: LocalLLMConfig | None = None):
        self.config = config or LocalLLMConfig.from_env()
        self._opener = build_opener(_NoRedirect())
        self._admission = threading.BoundedSemaphore(
            self.config.max_concurrency + self.config.max_queue_depth
        )
        self._workers = threading.BoundedSemaphore(self.config.max_concurrency)
        self._runtime_version = ""

    @staticmethod
    def _failure(status: str, message: str, request_id: str = "") -> dict[str, Any]:
        return {
            "status": status,
            "text": "",
            "request_id": request_id,
            "error": {"code": status, "message": str(message)[:160]},
            "trusted": False,
        }

    def _request_json(
        self, method: str, path: str, payload: dict[str, Any] | None, timeout: float
    ) -> dict[str, Any]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.config.base_url}{path}", data=data, method=method, headers=headers
        )
        try:
            with self._opener.open(request, timeout=max(timeout, 0.05)) as response:
                raw = response.read(self.config.max_response_bytes + 1)
        except HTTPError as exc:
            if exc.code == 503:
                raise RuntimeError("QUEUE_FULL") from exc
            raise RuntimeError("UNAVAILABLE") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RuntimeError("TIMEOUT") from exc
        except (URLError, OSError) as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, (TimeoutError, socket.timeout)):
                raise RuntimeError("TIMEOUT") from exc
            raise RuntimeError("UNAVAILABLE") from exc
        if len(raw) > self.config.max_response_bytes:
            raise RuntimeError("INVALID_OUTPUT")
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("INVALID_OUTPUT") from exc
        if not isinstance(result, dict):
            raise RuntimeError("INVALID_OUTPUT")
        return result

    def health(self) -> dict[str, Any]:
        if not self.config.enabled:
            return self._failure("DISABLED", "local LLM is disabled")
        try:
            response = self._request_json("GET", "/api/version", None, self.config.timeout_seconds)
            version = str(response.get("version") or "").strip()
            if not version or len(version) > 64:
                raise RuntimeError("INVALID_OUTPUT")
            self._runtime_version = version
            return {
                "status": "OK",
                "runtime": "ollama",
                "runtime_version": version,
                "contract_version": CONTRACT_VERSION,
                "enabled": True,
            }
        except RuntimeError as exc:
            code = str(exc) if str(exc) in {
                "UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "QUEUE_FULL"
            } else "UNAVAILABLE"
            return self._failure(code, "local LLM health check failed")

    def ready(self) -> dict[str, Any]:
        if not self.config.enabled:
            return self._failure("DISABLED", "local LLM is disabled")
        health = self.health()
        if health["status"] != "OK":
            return health
        try:
            response = self._request_json("GET", "/api/tags", None, self.config.timeout_seconds)
            models = response.get("models")
            if not isinstance(models, list):
                raise RuntimeError("INVALID_OUTPUT")
            installed = [
                str(item.get("name") or "") for item in models if isinstance(item, dict)
            ]
            if self.config.model not in installed:
                return self._failure("UNAVAILABLE", "approved local model is not installed")
            return {
                "status": "READY",
                "model": self.config.model,
                "runtime_version": self._runtime_version,
                "contract_version": CONTRACT_VERSION,
            }
        except RuntimeError as exc:
            code = str(exc) if str(exc) in {
                "UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "QUEUE_FULL"
            } else "UNAVAILABLE"
            return self._failure(code, "local LLM readiness check failed")

    def model_metadata(self) -> dict[str, Any]:
        ready = self.ready()
        if ready["status"] != "READY":
            return ready
        try:
            tags = self._request_json("GET", "/api/tags", None, self.config.timeout_seconds)
            installed = next(
                item for item in tags["models"]
                if isinstance(item, dict) and item.get("name") == self.config.model
            )
            shown = self._request_json(
                "POST", "/api/show", {"model": self.config.model}, self.config.timeout_seconds
            )
            details = shown.get("details")
            if not isinstance(details, dict):
                raise RuntimeError("INVALID_OUTPUT")
            size = installed.get("size")
            if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
                raise RuntimeError("INVALID_OUTPUT")
            metadata = {
                "status": "OK",
                "name": self.config.model,
                "runtime": "ollama",
                "runtime_version": self._runtime_version,
                "parameter_class": str(details.get("parameter_size") or "")[:32],
                "quantization": str(details.get("quantization_level") or "")[:32],
                "format": str(details.get("format") or "")[:32],
                "family": str(details.get("family") or "")[:32],
                "file_size_bytes": size,
                "cpu_only_required": True,
                "persistent_loading": True,
            }
            if not metadata["parameter_class"] or not metadata["quantization"]:
                raise RuntimeError("INVALID_OUTPUT")
            return metadata
        except (RuntimeError, KeyError, StopIteration, TypeError):
            return self._failure("INVALID_OUTPUT", "local model metadata is invalid")

    def generate(
        self, prompt: str, max_tokens: int = 128, temperature: float = 0.2
    ) -> dict[str, Any]:
        if not self.config.enabled:
            return self._failure("DISABLED", "local LLM is disabled")
        if not isinstance(prompt, str) or not prompt.strip():
            return self._failure("INVALID_REQUEST", "prompt must be a nonempty string")
        if len(prompt) > self.config.max_prompt_chars:
            return self._failure("INVALID_REQUEST", "prompt exceeds configured character limit")
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int):
            return self._failure("INVALID_REQUEST", "max_tokens must be an integer")
        if not 1 <= max_tokens <= self.config.max_output_tokens:
            return self._failure("INVALID_REQUEST", "max_tokens exceeds configured limit")
        if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
            return self._failure("INVALID_REQUEST", "temperature must be numeric")
        temperature = float(temperature)
        if not math.isfinite(temperature) or not 0.0 <= temperature <= 1.0:
            return self._failure("INVALID_REQUEST", "temperature must be between 0 and 1")

        body = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": -1,
            "options": {
                "num_predict": max_tokens,
                "num_ctx": 2048,
                "num_gpu": 0,
                "temperature": temperature,
            },
        }
        request_id = "LLMREQ-" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]
        if not self._admission.acquire(blocking=False):
            return self._failure("QUEUE_FULL", "local inference admission queue is full", request_id)

        started = time.perf_counter()
        acquired_worker = False
        try:
            deadline = started + self.config.timeout_seconds
            acquired_worker = self._workers.acquire(
                timeout=max(0.0, deadline - time.perf_counter())
            )
            if not acquired_worker:
                return self._failure("TIMEOUT", "local inference queue wait timed out", request_id)
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return self._failure("TIMEOUT", "local inference timed out", request_id)
            try:
                response = self._request_json("POST", "/api/generate", body, remaining)
            except RuntimeError as exc:
                code = str(exc) if str(exc) in {
                    "UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "QUEUE_FULL"
                } else "UNAVAILABLE"
                return self._failure(code, "local inference failed safely", request_id)

            text = response.get("response")
            eval_count = response.get("eval_count")
            durations = (response.get("total_duration"), response.get("load_duration"))
            if (
                response.get("model") != self.config.model
                or response.get("done") is not True
                or not isinstance(text, str)
                or not text.strip()
                or len(text) > max(1024, max_tokens * 64)
                or isinstance(eval_count, bool)
                or not isinstance(eval_count, int)
                or not 0 <= eval_count <= max_tokens
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in durations)
            ):
                return self._failure("INVALID_OUTPUT", "local runtime returned invalid output", request_id)
            if not self._runtime_version:
                version = self.health()
                if version["status"] != "OK":
                    return self._failure("INVALID_OUTPUT", "runtime version is unavailable", request_id)
            return {
                "status": "OK",
                "text": text,
                "request_id": request_id,
                "model_version": self.config.model,
                "runtime_version": self._runtime_version,
                "contract_version": CONTRACT_VERSION,
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "generated_tokens": eval_count,
                "output_chars": len(text),
                "runtime_total_ms": round(durations[0] / 1_000_000, 3),
                "runtime_load_ms": round(durations[1] / 1_000_000, 3),
                "trusted": False,
            }
        finally:
            if acquired_worker:
                self._workers.release()
            self._admission.release()
