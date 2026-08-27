"""Exactly-three-request local Phase 19 acceptance smoke.

This validation utility uses deterministic repository fixtures and the current
read-only registry artifact. Model output may be accepted or safely rejected.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEARNING = ROOT / "learning_agent"
if str(LEARNING) not in sys.path:
    sys.path.insert(0, str(LEARNING))

from deception_engine.strategy_registry import StrategyRegistry
from local_llm.client import LocalLLMClient

from .generator import DecoyGenerationAgent
from .test_decoy_generation import generation_request


def main() -> int:
    registry = StrategyRegistry.load().to_dict()
    agent = DecoyGenerationAgent(LocalLLMClient(), registry)
    cases = (
        ("schema", ["schema_metadata", "synthetic_rows"]),
        ("backup_migration", ["backup_archive_metadata", "migration_artifact"]),
        ("audit", ["audit_history"]),
    )
    records = []
    for label, asset_types in cases:
        started = time.perf_counter()
        result = agent.generate(generation_request(asset_types))
        records.append({
            "label": label,
            "status": result.get("status"),
            "request_latency_ms": round((time.perf_counter() - started) * 1000, 3),
            "attempt_count": result.get("attempt_count", 0),
            "repair_count": result.get("repair_count", 0),
            "phase17_status": (result.get("phase17_handoff") or {}).get("status"),
            "database_asset_count": (result.get("phase17_handoff") or {}).get(
                "database_asset_count", 0
            ),
            "database_execution": (result.get("phase17_handoff") or {}).get(
                "database_execution", False
            ),
            "trusted": result.get("trusted"),
            "authority": result.get("authority"),
        })
    candidate_statuses = {"CANDIDATE_READY", "CANDIDATE_REQUIRES_SANDBOX"}
    summary = {
        "generator_request_count": len(records),
        "successful_request_count": sum(item["status"] in candidate_statuses for item in records),
        "repair_count": sum(item["repair_count"] for item in records),
        "candidate_count": sum(item["status"] in candidate_statuses for item in records),
        "rejection_count": sum(item["status"] not in candidate_statuses for item in records),
        "median_request_latency_ms": round(
            statistics.median(item["request_latency_ms"] for item in records), 3
        ),
        "records": records,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if len(records) == 3 and all(
        item["trusted"] is False
        and item["database_execution"] is not True
        and not (item["authority"] or {}).get("deployable", False)
        for item in records
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
