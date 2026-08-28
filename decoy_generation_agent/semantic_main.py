"""JSON stdin/stdout entry point for Phase 19.1 semantic proposals."""

from __future__ import annotations

import json
import sys

from local_llm.semantic_client import SemanticLLMClient

from .semantic_proposal import SemanticProposalAgent


def main() -> int:
    try:
        envelope = json.load(sys.stdin)
        if not isinstance(envelope, dict) or set(envelope) != {"semantic_request", "registry_snapshot"}:
            raise ValueError("complete semantic proposal envelope is required")
        result = SemanticProposalAgent(SemanticLLMClient(), envelope["registry_snapshot"]).propose(envelope["semantic_request"])
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {"status": "REJECTED", "error": {"code": "INVALID_ENVELOPE", "message": str(exc)[:160]}, "trusted": False}
    json.dump(result, sys.stdout, sort_keys=True, separators=(",", ":"), allow_nan=False)
    sys.stdout.write("\n")
    return 0 if result.get("status") == "SEMANTIC_CANDIDATE_READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())

