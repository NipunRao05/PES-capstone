"""CLI for one bounded retrospective session analysis."""

from __future__ import annotations

import argparse
import json

try:
    from .client import SafeInternalEvidenceClient
    from .retrospective import RetrospectiveLearningAgent
except ImportError:  # Direct script execution in the documented local container.
    from client import SafeInternalEvidenceClient
    from retrospective import RetrospectiveLearningAgent


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze one completed honeypot session")
    parser.add_argument("session_id")
    parser.add_argument("--session-api", default="http://session-module:8003")
    parser.add_argument("--registry-api", default="http://deception-engine:8001")
    args = parser.parse_args()
    try:
        telemetry, reward, registry = SafeInternalEvidenceClient(
            args.session_api, args.registry_api
        ).load_session(args.session_id)
        report = RetrospectiveLearningAgent().analyze(telemetry, reward, registry)
    except ValueError as exc:
        print(json.dumps({
            "status": "REJECTED",
            "error": str(exc)[:256],
        }, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
