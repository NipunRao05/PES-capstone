"""Fixed ten-case Phase 19.1 live benchmark, one case per invocation."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEARNING = ROOT / "learning_agent"
if str(LEARNING) not in sys.path:
    sys.path.insert(0, str(LEARNING))

from learning_agent.review import BlueTeamReviewStore
from local_llm.semantic_client import SemanticLLMClient
from test_review import FIXED_TIME, valid_proposal

from .semantic_proposal import SEMANTIC_REQUEST_VERSION, SemanticProposalAgent


_CASES = (
    ("route_archive", "mysql", "Northstar Parcel Labs", "fictional logistics research", ["routine shipment tracking"]),
    ("vendor_review", "postgres", "Blue Lantern Works", "fictional procurement research", ["vendor directory"]),
    ("retention_map", "mysql", "Cedar Signal Labs", "fictional records research", ["retention schedule"]),
    ("migration_notes", "postgres", "Silver Orchard Systems", "fictional migration research", ["generic backup inventory"]),
    ("batch_audit", "mysql", "Harbor Kite Labs", "fictional batch processing research", ["routine audit log"]),
    ("legacy_index", "postgres", "Juniper Transit Lab", "fictional transit research", ["active route catalog"]),
    ("review_queue", "mysql", "Amber Relay Works", "fictional operations research", ["support queue"]),
    ("archive_manifest", "postgres", "Marble Finch Labs", "fictional archive research", ["generic file manifest"]),
    ("exception_ledger", "mysql", "Willow Circuit Works", "fictional workflow research", ["standard exception list"]),
    ("handoff_history", "postgres", "Quiet Harbor Labs", "fictional handoff research", ["current assignment history"]),
)


def benchmark_cases() -> list[dict]:
    proposal = valid_proposal()
    review = BlueTeamReviewStore().review(
        proposal, reviewer="blue-team-local", decision="APPROVE",
        reason="Evidence supports bounded semantic validation.", timestamp=FIXED_TIME,
    )
    result = []
    for label, protocol, company, industry, themes in _CASES:
        result.append({
            "label": label,
            "request": {
                "request_version": SEMANTIC_REQUEST_VERSION,
                "fictional_persona_summary": {
                    "company_name": company, "industry": industry,
                    "environment_label": f"{label}_lab", "fictional": True,
                },
                "proposal": proposal, "review": review,
                "strategy_requirements": {
                    "strategy_id": "D8", "name": "UNMODELED_RECURRING_BEHAVIOR_LURE",
                    "required_state": ["session_id", "protocol"], "forbidden_state": [],
                    "activation_conditions": ["reviewed recurring behavior gap is present"],
                    "compatible_personas": ["script", "automated_tool", "human_attacker"],
                    "risk_level": "medium", "resource_cost": "low",
                },
                "supported_protocol": protocol, "existing_semantic_themes": themes,
                "synthetic_schema_summary": [{"table": f"{label}_index", "columns": ["record_id", "status_label"]}],
            },
        })
    return result


def run_case(index: int) -> dict:
    from deception_engine.strategy_registry import StrategyRegistry

    case = benchmark_cases()[index]
    client = SemanticLLMClient()
    registry = StrategyRegistry.load().to_dict()
    started = time.perf_counter()
    result = SemanticProposalAgent(client, registry).propose(case["request"])
    elapsed = round((time.perf_counter() - started) * 1000, 3)
    attempts = result.get("attempts") or []
    last = attempts[-1] if attempts else {}
    resource = client.resource_snapshot()
    return {
        "case_index": index, "label": case["label"],
        "status": result.get("status"),
        "schema_conforming": last.get("structural_validation") == "PASS",
        "semantic_validator": "PASS" if result.get("status") == "SEMANTIC_CANDIDATE_READY" else "FAIL",
        "safety_validator": "PASS" if result.get("status") == "SEMANTIC_CANDIDATE_READY" else "FAIL_CLOSED",
        "repair_used": result.get("repair_count", 0) > 0,
        "attempt_count": result.get("attempt_count", 0), "latency_ms": elapsed,
        "prompt_tokens": sum(item.get("prompt_tokens") or 0 for item in attempts),
        "output_tokens": sum(item.get("output_tokens") or 0 for item in attempts),
        "model_runtime_metadata": result.get("model_runtime_metadata"),
        "loaded_model_bytes": resource.get("loaded_size_bytes"),
        "loaded_vram_bytes": resource.get("loaded_vram_bytes"),
        "cpu_only_observed": resource.get("cpu_only_observed"),
        "semantic_proposal_id": result.get("semantic_proposal_id"),
        "phase17_status": (result.get("phase17_handoff") or {}).get("status"),
        "candidate_status": result.get("candidate_status"),
        "registry_status": result.get("registry_status"),
        "reasoning_persisted": "<think" in json.dumps(result, sort_keys=True).lower(),
        "rejection_reason": result.get("rejection_reason", ""),
        "authority": result.get("authority"),
    }


def summarize(records: list[dict]) -> dict:
    latencies = [item["latency_ms"] for item in records]
    return {
        "benchmark_version": "semantic-proposal-benchmark-v1", "fixed_case_count": len(records),
        "schema_conforming_count": sum(item["schema_conforming"] for item in records),
        "semantic_pass_count": sum(item["semantic_validator"] == "PASS" for item in records),
        "safety_pass_count": sum(item["safety_validator"] == "PASS" for item in records),
        "repair_count": sum(item["repair_used"] for item in records),
        "median_latency_ms": round(statistics.median(latencies), 3) if latencies else None,
        "worst_latency_ms": round(max(latencies), 3) if latencies else None,
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-index", type=int, choices=range(10))
    args = parser.parse_args()
    if args.case_index is None:
        value = summarize([run_case(index) for index in range(10)])
    else:
        value = run_case(args.case_index)
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
