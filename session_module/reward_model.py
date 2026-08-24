"""Calibration-safe deception rewards derived from linked Phase 8 telemetry."""

from __future__ import annotations

import copy
import math
from typing import Any

REWARD_VERSION = "deception-reward-v1"
CALIBRATION_STATUS = "REQUIRES_PHASE_10_CALIBRATION"
_APPROVED_STRATEGIES = {"D0", "D1", "D2", "D3", "D4", "D6"}


def _number(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return number


def _integer(value: Any, field: str) -> int:
    number = _number(value, field)
    if not number.is_integer():
        raise ValueError(f"{field} must be an integer")
    return int(number)


def _rounded(value: float) -> float:
    return round(float(value), 6)


class DeceptionRewardModel:
    """Produce deterministic vectors without inventing uncalibrated weights."""

    @staticmethod
    def decision(linked_record: dict) -> dict:
        if not isinstance(linked_record, dict):
            raise ValueError("linked telemetry record must be an object")
        decision = linked_record.get("decision")
        outcome = linked_record.get("outcome")
        if not isinstance(decision, dict) or not isinstance(outcome, dict):
            raise ValueError("decision and outcome objects are required")
        decision_id = str(decision.get("decision_id") or "").strip()[:128]
        session_id = str(decision.get("session_id") or "").strip()[:256]
        if (
            not decision_id
            or not session_id
            or outcome.get("decision_id") != decision_id
            or outcome.get("session_id") != session_id
        ):
            raise ValueError("decision/outcome linkage is invalid")

        base = {
            "reward_version": REWARD_VERSION,
            "decision_id": decision_id,
            "session_id": session_id,
            "selected_action": str(decision.get("selected_action") or "")[:32],
            "calibration_status": CALIBRATION_STATUS,
            "weight_profile": None,
            "composite_reward": None,
        }
        if outcome.get("final") is not True:
            return {**base, "status": "PENDING", "dimensions": None}

        progression = outcome.get("attacker_progression")
        if not isinstance(progression, dict):
            raise ValueError("attacker_progression must be an object")
        allowed = decision.get("allowed_actions")
        selected = decision.get("selected_action")
        default = decision.get("rule_default_action")
        allowed_set = set(allowed) if isinstance(allowed, list) else set()
        safety_violations = 0 if (
            isinstance(allowed, list)
            and allowed_set
            and allowed_set.issubset(_APPROVED_STRATEGIES)
            and selected in _APPROVED_STRATEGIES
            and default in _APPROVED_STRATEGIES
            and selected in allowed_set
            and default in allowed_set
            and selected == default
            and str(decision.get("selector_type") or "") == "rule"
            and str(decision.get("policy_version") or "") == "rule-v1"
            and not isinstance(decision.get("confidence"), bool)
            and decision.get("confidence") == 1.0
        ) else 1

        dimensions = {
            "engagement": {
                "queries_after_decision": _integer(
                    outcome.get("queries_after_decision"), "queries_after_decision"
                ),
                "duration_seconds": _rounded(_number(
                    outcome.get("session_duration_after_decision"),
                    "session_duration_after_decision",
                )),
            },
            "intelligence_gain": {
                "new_tables": _integer(
                    outcome.get("new_tables_accessed"), "new_tables_accessed"
                ),
                "new_MITRE_techniques": _integer(
                    outcome.get("new_MITRE_techniques"), "new_MITRE_techniques"
                ),
            },
            "behavior_novelty": {
                "new_query_families": _integer(
                    outcome.get("new_query_families"), "new_query_families"
                ),
            },
            "MITRE_progression": {
                "advanced": 1 if progression.get("advanced") is True else 0,
                "from_stage": str(progression.get("from_stage") or "")[:64],
                "to_stage": str(progression.get("to_stage") or "")[:64],
            },
            "meaningful_trap_interaction": {
                "interactions": _integer(
                    outcome.get("trap_interactions"), "trap_interactions"
                ),
            },
            "latency_penalty": {
                "milliseconds": _rounded(_number(outcome.get("latency"), "latency")),
            },
            "resource_penalty": {
                "CPU_milliseconds": _rounded(_number(
                    outcome.get("CPU_cost"), "CPU_cost"
                )),
                "serialized_bytes": _integer(
                    outcome.get("memory_cost"), "memory_cost"
                ),
            },
            "protocol_error_penalty": {
                "count": _integer(
                    outcome.get("protocol_errors"), "protocol_errors"
                ),
            },
            "state_inconsistency_penalty": {
                "count": _integer(
                    outcome.get("state_inconsistencies"),
                    "state_inconsistencies",
                ),
            },
            "safety_penalty": {"count": safety_violations},
        }
        return {**base, "status": "COMPLETE", "dimensions": dimensions}

    def session(self, session_record: dict) -> dict:
        if not isinstance(session_record, dict):
            raise ValueError("session telemetry must be an object")
        session_id = str(session_record.get("session_id") or "").strip()[:256]
        records = session_record.get("records")
        if not session_id or not isinstance(records, list) or not records:
            raise ValueError("nonempty session telemetry is required")
        rewards = [self.decision(record) for record in records]
        if any(reward["session_id"] != session_id for reward in rewards):
            raise ValueError("cross-session reward records are forbidden")
        decision_ids = [reward["decision_id"] for reward in rewards]
        if len(set(decision_ids)) != len(decision_ids):
            raise ValueError("duplicate decision rewards are forbidden")
        base = {
            "reward_version": REWARD_VERSION,
            "session_id": session_id,
            "decision_count": len(rewards),
            "calibration_status": CALIBRATION_STATUS,
            "weight_profile": None,
            "composite_reward": None,
            "aggregation": "per-decision-arithmetic-mean",
            "per_decision": copy.deepcopy(rewards),
        }
        if any(reward["status"] != "COMPLETE" for reward in rewards):
            return {**base, "status": "PENDING", "aggregate_dimensions": None}

        numeric_paths = (
            ("engagement", "queries_after_decision"),
            ("engagement", "duration_seconds"),
            ("intelligence_gain", "new_tables"),
            ("intelligence_gain", "new_MITRE_techniques"),
            ("behavior_novelty", "new_query_families"),
            ("MITRE_progression", "advanced"),
            ("meaningful_trap_interaction", "interactions"),
            ("latency_penalty", "milliseconds"),
            ("resource_penalty", "CPU_milliseconds"),
            ("resource_penalty", "serialized_bytes"),
            ("protocol_error_penalty", "count"),
            ("state_inconsistency_penalty", "count"),
            ("safety_penalty", "count"),
        )
        aggregate: dict[str, dict[str, float]] = {}
        for dimension, metric in numeric_paths:
            values = [reward["dimensions"][dimension][metric] for reward in rewards]
            aggregate.setdefault(dimension, {})[metric] = _rounded(
                sum(values) / len(values)
            )
        return {**base, "status": "COMPLETE", "aggregate_dimensions": aggregate}
