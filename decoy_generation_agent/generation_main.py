"""JSON stdin/stdout entry point for the offline Phase 19 generator."""

from __future__ import annotations

import json
import sys

from local_llm.client import LocalLLMClient

from .generator import DecoyGenerationAgent


def main() -> int:
    try:
        envelope = json.load(sys.stdin)
        if not isinstance(envelope, dict) or set(envelope) != {
            "generation_request", "registry_snapshot"
        }:
            raise ValueError("complete generator envelope is required")
        result = DecoyGenerationAgent(
            LocalLLMClient(), envelope["registry_snapshot"]
        ).generate(envelope["generation_request"])
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {
            "status": "REJECTED",
            "error": {"code": "INVALID_ENVELOPE", "message": str(exc)[:160]},
            "trusted": False,
        }
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"), allow_nan=False)
    sys.stdout.write("\n")
    return 0 if result.get("status") in {
        "CANDIDATE_READY", "CANDIDATE_REQUIRES_SANDBOX"
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
