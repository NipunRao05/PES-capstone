"""Deterministic similar-session retrieval and counterfactual estimation.

Phase 14 is offline and read-only. It compares only completed, independently
validated strategy decisions. It does not train a model, create strategies,
change policy, or claim causal certainty from observational evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
from typing import Any

try:
    from .retrospective import RetrospectiveLearningAgent
except ImportError:  # Direct script execution in the documented local container.
    from retrospective import RetrospectiveLearningAgent

SIMILARITY_VERSION = "similar-session-v1"
COUNTERFACTUAL_VERSION = "counterfactual-estimate-v1"
CONTEXT_VERSION = "counterfactual-context-v1"

_APPROVED_ACTIONS = ("D0", "D1", "D2", "D3", "D4", "D6")
_COUNT_FEATURES = (
    "catalog_query_count",
    "metadata_query_count",
    "credential_keyword_count",
    "backup_keyword_count",
    "sensitive_table_interest",
    "role_enumeration_count",
    "privilege_escalation_attempts",
    "destructive_query_count",
    "trap_trigger_count",
    "unique_table_count",
    "unique_query_family_count",
    "mitre_technique_count",
    "session_depth",
)
_STAGE_ORDER = {
    "": 0,
    "recon": 1,
    "enumeration": 2,
    "privilege_discovery": 3,
    "credential_access": 4,
    "data_discovery": 5,
    "collection": 6,
    "exploitation": 7,
    "exfiltration": 8,
}
_REWARD_METRICS = (
    ("engagement_queries", "engagement", "queries_after_decision", "MAXIMIZE"),
    ("engagement_duration_seconds", "engagement", "duration_seconds", "MAXIMIZE"),
    ("new_tables", "intelligence_gain", "new_tables", "MAXIMIZE"),
    ("new_mitre_techniques", "intelligence_gain", "new_MITRE_techniques", "MAXIMIZE"),
    ("new_query_families", "behavior_novelty", "new_query_families", "MAXIMIZE"),
    ("mitre_progression", "MITRE_progression", "advanced", "MAXIMIZE"),
    ("trap_interactions", "meaningful_trap_interaction", "interactions", "MAXIMIZE"),
    ("latency_milliseconds", "latency_penalty", "milliseconds", "MINIMIZE"),
    ("cpu_milliseconds", "resource_penalty", "CPU_milliseconds", "MINIMIZE"),
    ("serialized_bytes", "resource_penalty", "serialized_bytes", "MINIMIZE"),
    ("protocol_errors", "protocol_error_penalty", "count", "MINIMIZE"),
    ("state_inconsistencies", "state_inconsistency_penalty", "count", "MINIMIZE"),
    ("safety_penalty", "safety_penalty", "count", "MINIMIZE"),
)


def _finite_nonnegative(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return number


def _saturate(value: Any, field: str) -> float:
    number = _finite_nonnegative(value, field)
    return number / (1.0 + number)


class ContextNormalizer:
    """Convert minimized structured decision state into a bounded vector."""

    feature_names = (
        "bias", "protocol_mysql", "protocol_postgres", "risk_score",
        "mitre_stage_rank",
        *tuple(f"bounded_{name}" for name in _COUNT_FEATURES),
        *tuple(f"current_strategy_{action}" for action in _APPROVED_ACTIONS),
    )

    @classmethod
    def normalize(cls, state_before: dict) -> dict:
        if not isinstance(state_before, dict):
            raise ValueError("state_before must be an object")
        session = state_before.get("session_state") or {}
        behavior = state_before.get("behavior_state") or {}
        mitre = state_before.get("mitre_state") or {}
        if any(not isinstance(item, dict) for item in (session, behavior, mitre)):
            raise ValueError("structured context states must be objects")

        protocol = str(session.get("protocol") or behavior.get("protocol") or "").lower()
        if protocol == "postgresql":
            protocol = "postgres"
        if protocol not in {"mysql", "postgres"}:
            raise ValueError("supported protocol is required")
        risk = _finite_nonnegative(behavior.get("risk_score", 0.0), "risk_score")
        if risk > 1.0:
            raise ValueError("normalized risk_score cannot exceed one")
        stage = str(behavior.get("mitre_stage") or mitre.get("phase") or "").strip().lower()[:64]
        current = str(
            behavior.get("current_strategy") or session.get("strategy_id") or "D0"
        ).strip().upper()
        if current not in _APPROVED_ACTIONS:
            raise ValueError("current strategy must be approved")

        values = [
            1.0,
            1.0 if protocol == "mysql" else 0.0,
            1.0 if protocol == "postgres" else 0.0,
            risk,
            _STAGE_ORDER.get(stage, 0) / max(_STAGE_ORDER.values()),
        ]
        values.extend(_saturate(behavior.get(name, 0), name) for name in _COUNT_FEATURES)
        values.extend(1.0 if current == action else 0.0 for action in _APPROVED_ACTIONS)
        features = {
            name: round(value, 9) for name, value in zip(cls.feature_names, values)
        }
        group = f"{protocol}|{stage or 'none'}|risk-{min(int(risk * 4), 3)}"
        return {
            "context_version": CONTEXT_VERSION,
            "protocol": protocol,
            "context_group": group,
            "features": features,
            "vector": values,
        }


def _distance(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        raise ValueError("context vectors must have the same nonzero dimension")
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(left, right)) / len(left))


def _reward_vector(dimensions: dict) -> dict[str, float]:
    values: dict[str, float] = {}
    for name, dimension, metric, _objective in _REWARD_METRICS:
        section = dimensions.get(dimension)
        if not isinstance(section, dict):
            raise ValueError("validated reward dimensions are required")
        values[name] = _finite_nonnegative(section.get(metric), f"{dimension}.{metric}")
    return values


def _weighted_estimate(neighbors: list[dict], target_reward: dict) -> dict:
    total_weight = sum(item["similarity"] for item in neighbors)
    if total_weight <= 0:
        raise ValueError("positive similarity weight is required")
    estimates: dict[str, dict] = {}
    for name, _dimension, _metric, objective in _REWARD_METRICS:
        mean = sum(item["similarity"] * item["reward"][name] for item in neighbors) / total_weight
        variance = sum(
            item["similarity"] * (item["reward"][name] - mean) ** 2
            for item in neighbors
        ) / total_weight
        standard_error = math.sqrt(max(variance, 0.0) / len(neighbors))
        estimates[name] = {
            "objective": objective,
            "target_observed": round(target_reward[name], 9),
            "estimated_alternative": round(mean, 9),
            "estimated_difference": round(mean - target_reward[name], 9),
            "uncertainty": {
                "weighted_standard_deviation": round(math.sqrt(max(variance, 0.0)), 9),
                "standard_error": round(standard_error, 9),
                "approximate_95_percent_interval": [
                    round(max(0.0, mean - 1.96 * standard_error), 9),
                    round(mean + 1.96 * standard_error, 9),
                ],
            },
        }
    return estimates


def _validated_records(telemetry: dict, reward: dict, registry: dict) -> tuple[dict, list[dict]]:
    retrospective = RetrospectiveLearningAgent().analyze(telemetry, reward, registry)
    reward_by_id = {
        item["decision_id"]: item["dimensions"] for item in reward["per_decision"]
    }
    records: list[dict] = []
    for linked in telemetry["records"]:
        decision = linked["decision"]
        decision_id = decision["decision_id"]
        context = ContextNormalizer.normalize(decision["state_before"])
        records.append({
            "session_id": telemetry["session_id"],
            "decision_id": decision_id,
            "selected_action": decision["selected_action"],
            "allowed_actions": list(decision["allowed_actions"]),
            "context": context,
            "reward": _reward_vector(reward_by_id[decision_id]),
        })
    return retrospective, records


class SimilarSessionEvaluator:
    """Retrieve comparable decisions and estimate approved alternatives."""

    def __init__(self, neighbor_limit: int = 5, max_distance: float = 0.65):
        if isinstance(neighbor_limit, bool) or not isinstance(neighbor_limit, int):
            raise ValueError("neighbor_limit must be an integer")
        if not 1 <= neighbor_limit <= 25:
            raise ValueError("neighbor_limit must be between 1 and 25")
        if isinstance(max_distance, bool):
            raise ValueError("max_distance must be numeric")
        try:
            distance = float(max_distance)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_distance must be numeric") from exc
        if not math.isfinite(distance) or not 0 < distance <= 1:
            raise ValueError("max_distance must be in (0, 1]")
        self.neighbor_limit = neighbor_limit
        self.max_distance = distance

    def analyze(
        self,
        target_telemetry: dict,
        target_reward: dict,
        historical_sessions: list[dict],
        registry: dict,
    ) -> dict:
        if not isinstance(historical_sessions, list) or len(historical_sessions) > 50:
            raise ValueError("historical_sessions must be a list of at most 50 bundles")
        target_report, targets = _validated_records(
            target_telemetry, target_reward, registry
        )
        target_session_id = target_report["session_id"]
        history_records: list[dict] = []
        history_ids: list[str] = []
        for bundle in historical_sessions:
            if not isinstance(bundle, dict):
                raise ValueError("historical session bundles must be objects")
            telemetry = bundle.get("telemetry")
            reward = bundle.get("reward")
            if not isinstance(telemetry, dict) or not isinstance(reward, dict):
                raise ValueError("historical telemetry and reward are required")
            session_id = str(telemetry.get("session_id") or "")
            if session_id == target_session_id:
                continue
            if session_id in history_ids:
                raise ValueError("duplicate historical session evidence is not allowed")
            _report, records = _validated_records(telemetry, reward, registry)
            history_ids.append(session_id)
            history_records.extend(records)
        if len(history_records) > 12_500:
            raise ValueError("historical decision evidence exceeds the bounded limit")

        decisions: list[dict] = []
        for target in targets:
            comparable: list[dict] = []
            for candidate in history_records:
                if candidate["context"]["protocol"] != target["context"]["protocol"]:
                    continue
                distance = _distance(target["context"]["vector"], candidate["context"]["vector"])
                if distance > self.max_distance:
                    continue
                comparable.append({
                    **candidate,
                    "distance": distance,
                    "similarity": 1.0 - distance,
                })
            comparable.sort(key=lambda item: (
                item["distance"], item["session_id"], item["decision_id"]
            ))
            nearest = comparable[: self.neighbor_limit]
            nearest_summary = [
                {
                    "session_id": item["session_id"],
                    "decision_id": item["decision_id"],
                    "selected_action": item["selected_action"],
                    "distance": round(item["distance"], 9),
                    "similarity": round(item["similarity"], 9),
                    "context_group": item["context"]["context_group"],
                }
                for item in nearest
            ]
            alternatives: list[dict] = []
            for action in sorted(set(target["allowed_actions"]) - {target["selected_action"]}):
                support = [item for item in comparable if item["selected_action"] == action]
                support = support[: self.neighbor_limit]
                if not support:
                    alternatives.append({
                        "strategy_id": action,
                        "status": "INSUFFICIENT_EVIDENCE",
                        "claim": f"{action} has no qualifying same-protocol observations under similar contexts.",
                        "confidence": 0.0,
                        "confidence_label": "LOW",
                        "uncertainty_status": "UNBOUNDED_NO_SUPPORT",
                        "support_count": 0,
                        "supporting_session_ids": [],
                        "supporting_decision_ids": [],
                        "estimated_reward_dimensions": None,
                    })
                    continue
                mean_similarity = sum(item["similarity"] for item in support) / len(support)
                confidence = min(1.0, mean_similarity * min(1.0, len(support) / 5.0))
                label = "HIGH" if confidence >= 0.7 else "MEDIUM" if confidence >= 0.4 else "LOW"
                alternatives.append({
                    "strategy_id": action,
                    "status": "ESTIMATED_FROM_SIMILAR_CONTEXTS",
                    "claim": (
                        f"{action} is estimated from {len(support)} observed decision(s) under similar contexts; "
                        "no overall better/worse claim is made because reward weights are uncalibrated."
                    ),
                    "confidence": round(confidence, 9),
                    "confidence_label": label,
                    "confidence_basis": "support-count-and-context-similarity-only",
                    "uncertainty_status": "OBSERVATIONAL_ESTIMATE_NOT_CAUSAL",
                    "support_count": len(support),
                    "mean_similarity": round(mean_similarity, 9),
                    "supporting_session_ids": sorted({item["session_id"] for item in support}),
                    "supporting_decision_ids": sorted(item["decision_id"] for item in support),
                    "estimated_reward_dimensions": _weighted_estimate(support, target["reward"]),
                })
            decisions.append({
                "decision_id": target["decision_id"],
                "selected_action": target["selected_action"],
                "allowed_actions": copy.deepcopy(target["allowed_actions"]),
                "normalized_context": {
                    "context_version": CONTEXT_VERSION,
                    "protocol": target["context"]["protocol"],
                    "context_group": target["context"]["context_group"],
                    "features": target["context"]["features"],
                },
                "similar_session_retrieval": {
                    "status": "COMPLETE",
                    "method": "same-protocol-normalized-rms-nearest-neighbor-v1",
                    "neighbor_limit": self.neighbor_limit,
                    "max_distance": self.max_distance,
                    "supporting_session_ids": sorted({item["session_id"] for item in nearest}),
                    "neighbors": nearest_summary,
                },
                "counterfactual_estimates": alternatives,
                "overall_performance_judgment": "NOT_AVAILABLE_UNCALIBRATED_REWARD_WEIGHTS",
                "coverage_gap_assessment": {
                    "status": "DEFERRED_PHASE_15", "proposal_created": False,
                },
            })

        identity_payload = {
            "version": COUNTERFACTUAL_VERSION,
            "target_analysis_id": target_report["analysis_id"],
            "historical_session_ids": sorted(history_ids),
            "neighbor_limit": self.neighbor_limit,
            "max_distance": self.max_distance,
            "decisions": decisions,
        }
        digest = hashlib.sha256(json.dumps(
            identity_payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")).hexdigest()
        return {
            "analysis_version": COUNTERFACTUAL_VERSION,
            "analysis_id": "CF-" + digest[:24],
            "status": "COMPLETE",
            "scope": "OFFLINE_OBSERVATIONAL_COUNTERFACTUAL",
            "session_id": target_session_id,
            "authority": {
                "read_only": True,
                "live_policy_mutation": False,
                "model_training": False,
                "strategy_activation": False,
                "proposal_creation": False,
                "infrastructure_authority": False,
            },
            "evidence": {
                "target_retrospective_analysis_id": target_report["analysis_id"],
                "registry_version": target_report["evidence"]["registry_version"],
                "similarity_version": SIMILARITY_VERSION,
                "context_version": CONTEXT_VERSION,
                "reward_version": "deception-reward-v1",
                "reward_calibration_status": "REQUIRES_PHASE_10_CALIBRATION",
                "historical_session_ids": sorted(history_ids),
                "historical_decision_count": len(history_records),
                "raw_attacker_text_used": False,
            },
            "method_limits": {
                "causal_claims": False,
                "cross_protocol_comparison": False,
                "unsupported_action_estimation": False,
                "composite_reward_ranking": False,
            },
            "decision_analyses": decisions,
            "later_phase_boundaries": {
                "coverage_gap_detection": "PHASE_15",
                "proposal_creation": "PHASE_15",
                "live_policy_changes": "FORBIDDEN",
            },
        }
