"""Bounded structured-output client for the Phase 19.1 Ornith prototype."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .semantic_contract import (
    ORNITH_MODEL,
    SEMANTIC_CLIENT_VERSION,
    SEMANTIC_PROPOSAL_JSON_SCHEMA,
    SEMANTIC_SCHEMA_VERSION,
    SEMANTIC_SEED,
)

_ALLOWED_HOSTS = {"local-llm", "127.0.0.1", "localhost", "host.docker.internal"}
_THINK_TAG = re.compile(r"(?is)</?think(?:\s[^>]*)?>")


def _boolean(value: object, name: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return normalized == "true"


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _number(value: object, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _base_url(value: object) -> str:
    parsed = urlparse(str(value or "").strip())
    if (
        parsed.scheme != "http" or parsed.hostname not in _ALLOWED_HOSTS
        or parsed.port != 11434 or parsed.username is not None
        or parsed.password is not None or parsed.path not in {"", "/"}
        or parsed.query or parsed.fragment
    ):
        raise ValueError("SEMANTIC_LLM_URL must be an approved internal HTTP endpoint")
    return f"http://{parsed.hostname}:11434"


@dataclass(frozen=True)
class SemanticLLMConfig:
    enabled: bool = False
    base_url: str = "http://local-llm:11434"
    model: str = ORNITH_MODEL
    timeout_seconds: float = 300.0
    max_prompt_chars: int = 16_384
    max_output_tokens: int = 512
    context_length: int = 4096
    max_concurrency: int = 1
    max_queue_depth: int = 2
    keep_alive: str = "5m"
    seed: int = SEMANTIC_SEED
    max_response_bytes: int = 262_144

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "SemanticLLMConfig":
        values = os.environ if env is None else env
        model = str(values.get("SEMANTIC_LLM_MODEL", ORNITH_MODEL)).strip()
        if model != ORNITH_MODEL:
            raise ValueError("SEMANTIC_LLM_MODEL must be the Phase 19.1 Ornith model")
        keep_alive = str(values.get("SEMANTIC_LLM_KEEP_ALIVE", "5m")).strip()
        if keep_alive not in {"0", "5m"}:
            raise ValueError("SEMANTIC_LLM_KEEP_ALIVE must be 0 or 5m")
        context = _integer(values.get("SEMANTIC_LLM_CONTEXT", "4096"), "SEMANTIC_LLM_CONTEXT", 4096, 8192)
        if context not in {4096, 8192}:
            raise ValueError("SEMANTIC_LLM_CONTEXT must be 4096 or 8192")
        concurrency = _integer(values.get("SEMANTIC_LLM_MAX_CONCURRENCY", "1"), "SEMANTIC_LLM_MAX_CONCURRENCY", 1, 1)
        queue = _integer(values.get("SEMANTIC_LLM_MAX_QUEUE_DEPTH", "2"), "SEMANTIC_LLM_MAX_QUEUE_DEPTH", 2, 2)
        return cls(
            enabled=_boolean(values.get("SEMANTIC_LLM_ENABLED", "false"), "SEMANTIC_LLM_ENABLED"),
            base_url=_base_url(values.get("SEMANTIC_LLM_URL", "http://local-llm:11434")),
            model=model,
            timeout_seconds=_number(values.get("SEMANTIC_LLM_TIMEOUT_SECONDS", "300"), "SEMANTIC_LLM_TIMEOUT_SECONDS", 1.0, 300.0),
            max_prompt_chars=_integer(values.get("SEMANTIC_LLM_MAX_PROMPT_CHARS", "16384"), "SEMANTIC_LLM_MAX_PROMPT_CHARS", 4096, 16_384),
            max_output_tokens=_integer(values.get("SEMANTIC_LLM_MAX_OUTPUT_TOKENS", "512"), "SEMANTIC_LLM_MAX_OUTPUT_TOKENS", 1, 768),
            context_length=context,
            max_concurrency=concurrency,
            max_queue_depth=queue,
            keep_alive=keep_alive,
            seed=_integer(values.get("SEMANTIC_LLM_SEED", str(SEMANTIC_SEED)), "SEMANTIC_LLM_SEED", 0, 2_147_483_647),
        )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class SemanticLLMClient:
    """One-model, one-worker client with no attacker-facing authority."""

    def __init__(self, config: SemanticLLMConfig | None = None):
        self.config = config or SemanticLLMConfig.from_env()
        self._opener = build_opener(_NoRedirect())
        self._admission = threading.BoundedSemaphore(
            self.config.max_concurrency + self.config.max_queue_depth
        )
        self._workers = threading.BoundedSemaphore(self.config.max_concurrency)
        self._runtime_version = ""

    @staticmethod
    def _failure(status: str, message: str, request_id: str = "") -> dict[str, Any]:
        return {
            "status": status, "text": "", "request_id": request_id,
            "error": {"code": status, "message": str(message)[:160]},
            "trusted": False,
        }

    def _request_json(self, method: str, path: str, payload: dict | None, timeout: float) -> dict:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(f"{self.config.base_url}{path}", data=data, method=method, headers=headers)
        try:
            with self._opener.open(request, timeout=max(timeout, 0.05)) as response:
                raw = response.read(self.config.max_response_bytes + 1)
        except HTTPError as exc:
            raise RuntimeError("QUEUE_FULL" if exc.code == 503 else "UNAVAILABLE") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise RuntimeError("TIMEOUT") from exc
        except (URLError, OSError) as exc:
            reason = getattr(exc, "reason", None)
            raise RuntimeError("TIMEOUT" if isinstance(reason, (TimeoutError, socket.timeout)) else "UNAVAILABLE") from exc
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
            return self._failure("DISABLED", "semantic LLM is disabled")
        try:
            response = self._request_json("GET", "/api/version", None, self.config.timeout_seconds)
            version = str(response.get("version") or "").strip()
            if not version or len(version) > 64:
                raise RuntimeError("INVALID_OUTPUT")
            self._runtime_version = version
            return {"status": "OK", "runtime": "ollama", "runtime_version": version, "contract_version": SEMANTIC_CLIENT_VERSION, "enabled": True}
        except RuntimeError as exc:
            code = str(exc) if str(exc) in {"UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "QUEUE_FULL"} else "UNAVAILABLE"
            return self._failure(code, "semantic LLM health check failed")

    def ready(self) -> dict[str, Any]:
        if not self.config.enabled:
            return self._failure("DISABLED", "semantic LLM is disabled")
        health = self.health()
        if health["status"] != "OK":
            return health
        try:
            response = self._request_json("GET", "/api/tags", None, self.config.timeout_seconds)
            models = response.get("models")
            if not isinstance(models, list):
                raise RuntimeError("INVALID_OUTPUT")
            if self.config.model not in {str(item.get("name") or "") for item in models if isinstance(item, dict)}:
                return self._failure("UNAVAILABLE", "Phase 19.1 model is not installed")
            return {"status": "READY", "model": self.config.model, "runtime_version": self._runtime_version, "contract_version": SEMANTIC_CLIENT_VERSION}
        except RuntimeError as exc:
            code = str(exc) if str(exc) in {"UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "QUEUE_FULL"} else "UNAVAILABLE"
            return self._failure(code, "semantic LLM readiness check failed")

    def model_metadata(self) -> dict[str, Any]:
        ready = self.ready()
        if ready["status"] != "READY":
            return ready
        try:
            tags = self._request_json("GET", "/api/tags", None, self.config.timeout_seconds)
            installed = next(item for item in tags["models"] if isinstance(item, dict) and item.get("name") == self.config.model)
            shown = self._request_json("POST", "/api/show", {"model": self.config.model}, self.config.timeout_seconds)
            details = shown.get("details")
            size = installed.get("size")
            if not isinstance(details, dict) or isinstance(size, bool) or not isinstance(size, int) or size <= 0:
                raise RuntimeError("INVALID_OUTPUT")
            return {
                "status": "OK", "name": self.config.model, "runtime": "ollama",
                "runtime_version": self._runtime_version,
                "parameter_class": str(details.get("parameter_size") or "")[:32],
                "quantization": str(details.get("quantization_level") or "")[:32],
                "format": str(details.get("format") or "")[:32],
                "family": str(details.get("family") or "")[:32],
                "file_size_bytes": size, "cpu_only_required": True,
                "structured_schema_version": SEMANTIC_SCHEMA_VERSION,
            }
        except (RuntimeError, KeyError, StopIteration, TypeError):
            return self._failure("INVALID_OUTPUT", "semantic model metadata is invalid")

    def resource_snapshot(self) -> dict[str, Any]:
        """Return bounded Ollama load metadata; never host/container authority."""
        if not self.config.enabled:
            return self._failure("DISABLED", "semantic LLM is disabled")
        try:
            response = self._request_json("GET", "/api/ps", None, self.config.timeout_seconds)
            models = response.get("models")
            if not isinstance(models, list):
                raise RuntimeError("INVALID_OUTPUT")
            current = next(
                item for item in models
                if isinstance(item, dict) and item.get("name") == self.config.model
            )
            size = current.get("size")
            size_vram = current.get("size_vram", 0)
            if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (size, size_vram)):
                raise RuntimeError("INVALID_OUTPUT")
            return {
                "status": "OK", "model": self.config.model,
                "loaded_size_bytes": size, "loaded_vram_bytes": size_vram,
                "cpu_only_observed": size_vram == 0,
            }
        except (RuntimeError, StopIteration):
            return self._failure("UNAVAILABLE", "semantic model load metadata is unavailable")

    def generate_structured(self, prompt: str) -> dict[str, Any]:
        if not self.config.enabled:
            return self._failure("DISABLED", "semantic LLM is disabled")
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > self.config.max_prompt_chars:
            return self._failure("INVALID_REQUEST", "prompt is empty or exceeds its bound")
        body = {
            "model": self.config.model, "prompt": prompt, "stream": False,
            "think": False, "format": copy.deepcopy(SEMANTIC_PROPOSAL_JSON_SCHEMA),
            "keep_alive": self.config.keep_alive,
            "options": {
                "num_predict": self.config.max_output_tokens,
                "num_ctx": self.config.context_length, "num_gpu": 0,
                "temperature": 0.6, "top_p": 0.95, "top_k": 20,
                "min_p": 0.0, "presence_penalty": 0.0,
                "repeat_penalty": 1.0, "seed": self.config.seed,
            },
        }
        request_id = "SLLMREQ-" + hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]
        if not self._admission.acquire(blocking=False):
            return self._failure("QUEUE_FULL", "semantic inference queue is full", request_id)
        started = time.perf_counter()
        acquired_worker = False
        try:
            deadline = started + self.config.timeout_seconds
            acquired_worker = self._workers.acquire(timeout=max(0.0, deadline - time.perf_counter()))
            if not acquired_worker:
                return self._failure("TIMEOUT", "semantic inference queue wait timed out", request_id)
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return self._failure("TIMEOUT", "semantic inference timed out", request_id)
            try:
                response = self._request_json("POST", "/api/generate", body, remaining)
            except RuntimeError as exc:
                code = str(exc) if str(exc) in {"UNAVAILABLE", "TIMEOUT", "INVALID_OUTPUT", "QUEUE_FULL"} else "UNAVAILABLE"
                return self._failure(code, "semantic inference failed safely", request_id)
            text = response.get("response")
            prompt_count = response.get("prompt_eval_count")
            eval_count = response.get("eval_count")
            durations = (response.get("total_duration"), response.get("load_duration"), response.get("eval_duration"))
            if (
                response.get("model") != self.config.model or response.get("done") is not True
                or not isinstance(text, str) or not text.strip() or _THINK_TAG.search(text)
                or len(text) > 65_536
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (prompt_count, eval_count, *durations))
                or eval_count > self.config.max_output_tokens
            ):
                return self._failure("INVALID_OUTPUT", "semantic runtime returned invalid final output", request_id)
            if not self._runtime_version:
                health = self.health()
                if health["status"] != "OK":
                    return self._failure("INVALID_OUTPUT", "runtime version is unavailable", request_id)
            return {
                "status": "OK", "text": text, "request_id": request_id,
                "model_version": self.config.model, "runtime_version": self._runtime_version,
                "contract_version": SEMANTIC_CLIENT_VERSION,
                "schema_version": SEMANTIC_SCHEMA_VERSION,
                "schema_constraint_active": True, "thinking_requested": False,
                "reasoning_discarded": bool(str(response.get("thinking") or "")),
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "prompt_tokens": prompt_count, "generated_tokens": eval_count,
                "runtime_total_ms": round(durations[0] / 1_000_000, 3),
                "runtime_load_ms": round(durations[1] / 1_000_000, 3),
                "runtime_eval_ms": round(durations[2] / 1_000_000, 3),
                "trusted": False,
            }
        finally:
            if acquired_worker:
                self._workers.release()
            self._admission.release()
