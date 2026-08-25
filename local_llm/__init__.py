"""Bounded client contract for the optional Phase 18 local CPU LLM."""

from .client import LocalLLMClient
from .config import LocalLLMConfig

__all__ = ["LocalLLMClient", "LocalLLMConfig"]
