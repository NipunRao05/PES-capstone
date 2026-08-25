"""Strict Phase 18 local-LLM configuration."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse

MODEL_NAME = "qwen2.5:1.5b-instruct-q4_K_M"
CONTRACT_VERSION = "local-llm-client-v1"
_ALLOWED_HOSTS = {"local-llm", "127.0.0.1", "localhost", "host.docker.internal"}


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
        parsed.scheme != "http"
        or parsed.hostname not in _ALLOWED_HOSTS
        or parsed.port != 11434
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("LOCAL_LLM_URL must be an approved internal HTTP endpoint")
    return f"http://{parsed.hostname}:11434"


@dataclass(frozen=True)
class LocalLLMConfig:
    enabled: bool = False
    base_url: str = "http://local-llm:11434"
    model: str = MODEL_NAME
    timeout_seconds: float = 30.0
    max_prompt_chars: int = 4096
    max_output_tokens: int = 128
    max_concurrency: int = 1
    max_queue_depth: int = 2
    max_response_bytes: int = 262_144

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "LocalLLMConfig":
        values = os.environ if env is None else env
        model = str(values.get("LOCAL_LLM_MODEL", MODEL_NAME)).strip()
        if model != MODEL_NAME:
            raise ValueError("LOCAL_LLM_MODEL must be the single Phase 18 approved model")
        return cls(
            enabled=_boolean(values.get("LOCAL_LLM_ENABLED", "false"), "LOCAL_LLM_ENABLED"),
            base_url=_base_url(values.get("LOCAL_LLM_URL", "http://local-llm:11434")),
            model=model,
            timeout_seconds=_number(
                values.get("LOCAL_LLM_TIMEOUT_SECONDS", "30"),
                "LOCAL_LLM_TIMEOUT_SECONDS", 0.1, 120.0,
            ),
            max_prompt_chars=_integer(
                values.get("LOCAL_LLM_MAX_PROMPT_CHARS", "4096"),
                "LOCAL_LLM_MAX_PROMPT_CHARS", 1, 16_384,
            ),
            max_output_tokens=_integer(
                values.get("LOCAL_LLM_MAX_OUTPUT_TOKENS", "128"),
                "LOCAL_LLM_MAX_OUTPUT_TOKENS", 1, 512,
            ),
            max_concurrency=_integer(
                values.get("LOCAL_LLM_MAX_CONCURRENCY", "1"),
                "LOCAL_LLM_MAX_CONCURRENCY", 1, 2,
            ),
            max_queue_depth=_integer(
                values.get("LOCAL_LLM_MAX_QUEUE_DEPTH", "2"),
                "LOCAL_LLM_MAX_QUEUE_DEPTH", 0, 8,
            ),
        )
