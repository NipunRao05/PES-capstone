"""JSON-stdin CLI for Phase 17 candidate-strategy validation."""

from __future__ import annotations

import argparse
import json
import sys

try:
    from .candidate_validation import CandidateValidationPipeline
    from .client import SafeInternalEvidenceClient
except ImportError:  # Direct script execution in the documented local container.
    from candidate_validation import CandidateValidationPipeline
    from client import SafeInternalEvidenceClient


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate one reviewed candidate strategy")
    parser.add_argument("--registry-api", default="http://deception-engine:8001")
    args = parser.parse_args()
    try:
        validation_input = json.load(sys.stdin)
        registry = SafeInternalEvidenceClient(
            registry_base_url=args.registry_api
        ).load_registry()
        result = CandidateValidationPipeline().validate(validation_input, registry)
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)[:256]}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0 if result["status"] in {"VALIDATED", "VALIDATION_INCOMPLETE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
