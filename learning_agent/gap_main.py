"""CLI for bounded Phase 15 action-space gap detection."""

from __future__ import annotations

import argparse
import json

try:
    from .client import SafeInternalEvidenceClient
    from .gap_detection import ActionSpaceGapDetector
except ImportError:  # Direct script execution in the documented local container.
    from client import SafeInternalEvidenceClient
    from gap_detection import ActionSpaceGapDetector


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect evidence-backed action-space gaps")
    parser.add_argument("session_id")
    parser.add_argument("--session-api", default="http://session-module:8003")
    parser.add_argument("--registry-api", default="http://deception-engine:8001")
    parser.add_argument("--decision-limit", type=int, default=100)
    parser.add_argument("--history-limit", type=int, default=25)
    parser.add_argument("--max-distance", type=float, default=0.35)
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
        exclusions = [
            {"session_id": session_id, "reason": "INCOMPLETE_EVIDENCE"}
            for session_id in load_summary["incomplete_session_ids"]
        ] + [
            {"session_id": session_id, "reason": "UNAVAILABLE_EVIDENCE"}
            for session_id in load_summary["unavailable_session_ids"]
        ]
        result = ActionSpaceGapDetector(max_distance=args.max_distance).analyze(
            target_telemetry,
            target_reward,
            history,
            registry,
            historical_exclusions=exclusions,
        )
        result["history_load"] = load_summary
    except ValueError as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)[:256]}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
