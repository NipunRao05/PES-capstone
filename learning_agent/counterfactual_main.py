"""CLI for bounded Phase 14 similar-session analysis."""

from __future__ import annotations

import argparse
import json

try:
    from .client import SafeInternalEvidenceClient
    from .similarity import SimilarSessionEvaluator
except ImportError:  # Direct script execution in the documented local container.
    from client import SafeInternalEvidenceClient
    from similarity import SimilarSessionEvaluator


def main() -> int:
    parser = argparse.ArgumentParser(description="Estimate approved alternatives from similar sessions")
    parser.add_argument("session_id")
    parser.add_argument("--session-api", default="http://session-module:8003")
    parser.add_argument("--registry-api", default="http://deception-engine:8001")
    parser.add_argument("--decision-limit", type=int, default=100)
    parser.add_argument("--history-limit", type=int, default=25)
    parser.add_argument("--neighbor-limit", type=int, default=5)
    parser.add_argument("--max-distance", type=float, default=0.65)
    args = parser.parse_args()
    try:
        target_telemetry, target_reward, history, registry, load_summary = (
            SafeInternalEvidenceClient(args.session_api, args.registry_api)
            .load_session_with_history(
                args.session_id,
                decision_limit=args.decision_limit,
                history_limit=args.history_limit,
            )
        )
        report = SimilarSessionEvaluator(
            neighbor_limit=args.neighbor_limit,
            max_distance=args.max_distance,
        ).analyze(target_telemetry, target_reward, history, registry)
        report["history_load"] = load_summary
    except ValueError as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)[:256]}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
