"""Deterministic evidence-backed retrospective decision evaluation.

This module is read-only. It cannot train the live model, mutate policy, deploy
strategies, or perform the Phase 14/15 counterfactual and gap-analysis work.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections import Counter
from typing import Any

ANALYSIS_VERSION = "retrospective-learning-v1"
_MAX_RECORDS = 250
_MAX_INPUT_BYTES = 4_000_000
_FORBIDDEN_INPUT_KEYS = {
    "query", "query_raw", "query_normalized", "raw_sql", "fingerprint",
    "source_ip", "client_ip", "prompt", "password", "secret",
}
_REWARD_DIMENSIONS = {
    "engagement", "intelligence_gain", "behavior_novelty",
    "MITRE_progression", "meaningful_trap_interaction", "latency_penalty",
    "resource_penalty", "protocol_error_penalty",
    "state_inconsistency_penalty", "safety_penalty",
}
_STRATEGY_ID = re.compile(r"^D[0-9]+$")


def _bounded_text(value: Any, field: str, limit: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit:
        raise ValueError(f"{field} is required and must be <= {limit} characters")
    return text


def _nonnegative_number(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return number


def _nonnegative_int(value: Any, field: str) -> int:
    number = _nonnegative_number(value, field)
    if not number.is_integer():
        raise ValueError(f"{field} must be an integer")
    return int(number)


def _walk_input(value: Any, path: str = "input") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in _FORBIDDEN_INPUT_KEYS:
                raise ValueError(f"forbidden raw or identifying field: {key_text}")
            _walk_input(item, f"{path}.{key_text}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _walk_input(item, f"{path}[{index}]")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{path} must not contain nonfinite numbers")


def _input_size(*values: Any) -> int:
    try:
        encoded = json.dumps(
            values, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("inputs must be finite JSON values") from exc
    if len(encoded) > _MAX_INPUT_BYTES:
        raise ValueError("retrospective evidence exceeds the bounded input size")
    return len(encoded)


def _registry(registry: Any) -> tuple[str, dict[str, dict]]:
    if not isinstance(registry, dict) or registry.get("degraded") is not False:
        raise ValueError("a non-degraded strategy registry is required")
    version = _bounded_text(registry.get("registry_version"), "registry_version", 128)
    strategies = registry.get("strategies")
    listed = registry.get("approved_strategy_ids")
    if not isinstance(strategies, list) or not isinstance(listed, list):
        raise ValueError("registry strategy and approved lists are required")
    approved: dict[str, dict] = {}
    for strategy in strategies:
        if not isinstance(strategy, dict):
            raise ValueError("strategy entries must be objects")
        strategy_id = _bounded_text(strategy.get("strategy_id"), "strategy_id", 16)
        if not _STRATEGY_ID.fullmatch(strategy_id):
            raise ValueError("registry contains an invalid strategy ID")
        status = str(strategy.get("approval_status") or "").strip().upper()
        if status == "APPROVED":
            approved[strategy_id] = {
                "strategy_id": strategy_id,
                "name": _bounded_text(strategy.get("name"), "strategy name", 128),
                "validation_version": _bounded_text(
                    strategy.get("validation_version"), "validation_version", 128
                ),
            }
    listed_ids = [str(item or "").strip().upper() for item in listed]
    if not approved or set(listed_ids) != set(approved) or len(listed_ids) != len(approved):
        raise ValueError("registry approved strategy evidence is inconsistent")
    return version, approved


def _validate_reward_dimensions(dimensions: dict) -> None:
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
    for dimension, metric in numeric_paths:
        section = dimensions.get(dimension)
        if not isinstance(section, dict):
            raise ValueError(f"missing reward dimension: {dimension}")
        _nonnegative_number(section.get(metric), f"{dimension}.{metric}")
    integer_paths = (
        ("engagement", "queries_after_decision"),
        ("intelligence_gain", "new_tables"),
        ("intelligence_gain", "new_MITRE_techniques"),
        ("behavior_novelty", "new_query_families"),
        ("MITRE_progression", "advanced"),
        ("meaningful_trap_interaction", "interactions"),
        ("resource_penalty", "serialized_bytes"),
        ("protocol_error_penalty", "count"),
        ("state_inconsistency_penalty", "count"),
        ("safety_penalty", "count"),
    )
    for dimension, metric in integer_paths:
        _nonnegative_int(dimensions[dimension].get(metric), f"{dimension}.{metric}")


def _verify_reward_against_outcome(dimensions: dict, outcome: dict) -> None:
    """Recalculate every outcome-derived reward value and require an exact match."""
    progression = outcome.get("attacker_progression")
    if not isinstance(progression, dict):
        raise ValueError("attacker progression evidence is required")
    comparisons = (
        ("engagement", "queries_after_decision", outcome.get("queries_after_decision")),
        ("engagement", "duration_seconds", outcome.get("session_duration_after_decision")),
        ("intelligence_gain", "new_tables", outcome.get("new_tables_accessed")),
        ("intelligence_gain", "new_MITRE_techniques", outcome.get("new_MITRE_techniques")),
        ("behavior_novelty", "new_query_families", outcome.get("new_query_families")),
        ("MITRE_progression", "advanced", 1 if progression.get("advanced") is True else 0),
        ("meaningful_trap_interaction", "interactions", outcome.get("trap_interactions")),
        ("latency_penalty", "milliseconds", outcome.get("latency")),
        ("resource_penalty", "CPU_milliseconds", outcome.get("CPU_cost")),
        ("resource_penalty", "serialized_bytes", outcome.get("memory_cost")),
        ("protocol_error_penalty", "count", outcome.get("protocol_errors")),
        ("state_inconsistency_penalty", "count", outcome.get("state_inconsistencies")),
    )
    for dimension, metric, observed in comparisons:
        reward_value = _nonnegative_number(
            dimensions[dimension].get(metric), f"{dimension}.{metric}"
        )
        outcome_value = _nonnegative_number(observed, f"outcome.{metric}")
        if reward_value != outcome_value:
            raise ValueError("reward vector does not match linked observed outcome")
    mitre = dimensions["MITRE_progression"]
    if (
        str(mitre.get("from_stage") or "")
        != str(progression.get("from_stage") or "")
        or str(mitre.get("to_stage") or "")
        != str(progression.get("to_stage") or "")
    ):
        raise ValueError("reward MITRE progression does not match observed outcome")


def _reward_map(session_reward: Any, session_id: str) -> tuple[dict[str, dict], dict]:
    if not isinstance(session_reward, dict):
        raise ValueError("session reward must be an object")
    if (
        session_reward.get("status") != "COMPLETE"
        or session_reward.get("session_id") != session_id
        or session_reward.get("reward_version") != "deception-reward-v1"
        or session_reward.get("calibration_status")
        != "REQUIRES_PHASE_10_CALIBRATION"
        or session_reward.get("weight_profile") is not None
        or session_reward.get("composite_reward") is not None
    ):
        raise ValueError("a completed linked deception-reward-v1 session is required")
    per_decision = session_reward.get("per_decision")
    aggregate = session_reward.get("aggregate_dimensions")
    if not isinstance(per_decision, list) or not isinstance(aggregate, dict):
        raise ValueError("complete per-decision and aggregate rewards are required")
    rewards: dict[str, dict] = {}
    for reward in per_decision:
        if not isinstance(reward, dict) or reward.get("status") != "COMPLETE":
            raise ValueError("every decision reward must be complete")
        decision_id = _bounded_text(reward.get("decision_id"), "reward decision_id", 128)
        dimensions = reward.get("dimensions")
        if (
            reward.get("session_id") != session_id
            or reward.get("calibration_status")
            != "REQUIRES_PHASE_10_CALIBRATION"
            or reward.get("weight_profile") is not None
            or reward.get("composite_reward") is not None
            or not isinstance(dimensions, dict)
            or set(dimensions) != _REWARD_DIMENSIONS
            or decision_id in rewards
        ):
            raise ValueError("reward linkage or dimension evidence is invalid")
        _validate_reward_dimensions(dimensions)
        rewards[decision_id] = reward
    _walk_input(aggregate, "aggregate_dimensions")
    return rewards, copy.deepcopy(aggregate)


def _important_reasons(outcome: dict, dimensions: dict, decision: dict) -> list[str]:
    reasons: list[str] = []
    checks = (
        (outcome.get("trap_interactions"), "trap_interaction"),
        (outcome.get("new_MITRE_techniques"), "new_mitre_technique"),
        (outcome.get("new_tables_accessed"), "new_table_access"),
        (outcome.get("new_query_families"), "behavior_novelty"),
        (outcome.get("errors"), "error_observed"),
        (outcome.get("protocol_errors"), "protocol_error"),
        (outcome.get("state_inconsistencies"), "state_inconsistency"),
    )
    for value, reason in checks:
        if _nonnegative_number(value or 0, reason) > 0:
            reasons.append(reason)
    progression = outcome.get("attacker_progression") or {}
    if isinstance(progression, dict) and progression.get("advanced") is True:
        reasons.append("mitre_progression")
    if decision.get("selected_action") != decision.get("rule_default_action"):
        reasons.append("learned_selection")
    shadow = decision.get("shadow_evaluation")
    if isinstance(shadow, dict) and shadow.get("agreement") is False:
        reasons.append("shadow_disagreement")
    if dimensions["safety_penalty"]["count"] > 0:
        reasons.append("safety_penalty")
    return reasons


def _policy_assessment(decision: dict, outcome: dict, dimensions: dict) -> dict:
    signals: list[dict] = []
    for field, signal in (
        ("protocol_errors", "protocol_error_evidence"),
        ("state_inconsistencies", "state_inconsistency_evidence"),
        ("errors", "response_error_evidence"),
    ):
        count = int(_nonnegative_number(outcome.get(field, 0), field))
        if count:
            signals.append({"signal": signal, "count": count})
    safety_count = int(dimensions["safety_penalty"]["count"])
    if safety_count:
        signals.append({"signal": "safety_validation_failure", "count": safety_count})
    shadow = decision.get("shadow_evaluation")
    if isinstance(shadow, dict) and shadow.get("agreement") is False:
        signals.append({
            "signal": "shadow_disagreement",
            "calibration_status": str(shadow.get("calibration_status") or "UNKNOWN")[:64],
            "model_recommended": str(shadow.get("model_recommended") or "")[:16],
        })
    reason = str(decision.get("selection_reason") or "")[:64]
    if reason in {"model_unavailable", "model_uncalibrated", "low_confidence"}:
        signals.append({"signal": "learned_selection_fallback", "reason": reason})
    deterministic_failure = any(
        item["signal"] in {
            "protocol_error_evidence", "state_inconsistency_evidence",
            "safety_validation_failure",
        }
        for item in signals
    )
    return {
        "status": "REVIEW_REQUIRED" if deterministic_failure else "NO_DETERMINISTIC_POLICY_FAILURE",
        "signals": signals,
        "composite_reward_available": False,
        "performance_judgment": "INSUFFICIENT_UNCALIBRATED_REWARD_EVIDENCE",
    }


def _validate_decision_contract(decision: dict, selected: str, allowed: list[str]) -> None:
    default = str(decision.get("rule_default_action") or "").strip().upper()
    selector = str(decision.get("selector_type") or "").strip().lower()
    policy = str(decision.get("policy_version") or "").strip()
    if default not in allowed:
        raise ValueError("rule default is outside the recorded action space")
    confidence = decision.get("confidence")
    if isinstance(confidence, bool):
        raise ValueError("decision confidence must be numeric")
    try:
        confidence = float(confidence)
    except (TypeError, ValueError) as exc:
        raise ValueError("decision confidence must be numeric") from exc
    if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
        raise ValueError("decision confidence must be between zero and one")
    if selector == "rule":
        if selected != default or policy != "rule-v1" or confidence != 1.0:
            raise ValueError("recorded rule decision contract is invalid")
        return
    if (
        selector != "learned"
        or selected == default
        or policy != "bounded-learned-v1"
        or decision.get("learned_control") is not True
        or decision.get("selection_version") != "bounded-learned-selection-v1"
        or decision.get("calibration_status") != "CALIBRATED"
        or not str(decision.get("reward_profile_version") or "").strip()
    ):
        raise ValueError("recorded learned decision contract is invalid")


class RetrospectiveLearningAgent:
    """Evaluate completed decisions without authority over live components."""

    def analyze(self, session_telemetry: dict, session_reward: dict, registry: dict) -> dict:
        _input_size(session_telemetry, session_reward, registry)
        evidence_digest = hashlib.sha256(json.dumps(
            (session_telemetry, session_reward, registry),
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        _walk_input(session_telemetry, "session_telemetry")
        _walk_input(session_reward, "session_reward")
        _walk_input(registry, "strategy_registry")
        if not isinstance(session_telemetry, dict):
            raise ValueError("session telemetry must be an object")
        session_id = _bounded_text(session_telemetry.get("session_id"), "session_id", 256)
        records = session_telemetry.get("records")
        if not isinstance(records, list) or not 1 <= len(records) <= _MAX_RECORDS:
            raise ValueError("between 1 and 250 telemetry records are required")
        registry_version, approved = _registry(registry)
        rewards, aggregate = _reward_map(session_reward, session_id)
        if session_reward.get("decision_count") != len(records):
            raise ValueError("reward decision count does not match telemetry")

        observed_action_counts: Counter[str] = Counter()
        observed_action_decisions: dict[str, list[str]] = {}
        decision_ids: list[str] = []
        normalized_records: list[tuple[dict, dict, dict]] = []
        protocol = ""
        for linked in records:
            if not isinstance(linked, dict):
                raise ValueError("linked telemetry records must be objects")
            decision = linked.get("decision")
            outcome = linked.get("outcome")
            if not isinstance(decision, dict) or not isinstance(outcome, dict):
                raise ValueError("decision and outcome evidence is required")
            decision_id = _bounded_text(decision.get("decision_id"), "decision_id", 128)
            selected = _bounded_text(decision.get("selected_action"), "selected_action", 16)
            allowed = decision.get("allowed_actions")
            state_before = decision.get("state_before") or {}
            if (
                not isinstance(allowed, list)
                or any(not isinstance(action, str) or not action.strip() for action in allowed)
                or not isinstance(state_before, dict)
            ):
                raise ValueError("structured decision action/state evidence is invalid")
            allowed = [action.strip().upper() for action in allowed]
            session_state = state_before.get("session_state") or {}
            if not isinstance(session_state, dict):
                raise ValueError("structured session state evidence is invalid")
            observed_protocol = str(session_state.get("protocol") or "").strip().lower()
            if (
                decision.get("session_id") != session_id
                or decision.get("telemetry_version") != "strategy-telemetry-v1"
                or outcome.get("session_id") != session_id
                or outcome.get("telemetry_version") != "strategy-telemetry-v1"
                or outcome.get("decision_id") != decision_id
                or outcome.get("final") is not True
                or decision_id in decision_ids
                or decision_id not in rewards
                or rewards[decision_id].get("selected_action") != selected
                or not allowed
                or len(allowed) != len(set(allowed))
                or selected not in allowed
                or any(action not in approved for action in allowed)
            ):
                raise ValueError("telemetry decision linkage or action space is invalid")
            _bounded_text(decision.get("timestamp"), "decision timestamp", 64)
            _validate_decision_contract(decision, selected, allowed)
            if observed_protocol not in {"mysql", "postgres"}:
                raise ValueError("a supported structured protocol is required")
            if protocol and protocol != observed_protocol:
                raise ValueError("cross-protocol session evidence is invalid")
            protocol = observed_protocol
            decision_ids.append(decision_id)
            observed_action_counts[selected] += 1
            observed_action_decisions.setdefault(selected, []).append(decision_id)
            _verify_reward_against_outcome(rewards[decision_id]["dimensions"], outcome)
            normalized_records.append((decision, outcome, rewards[decision_id]))
        if set(decision_ids) != set(rewards):
            raise ValueError("telemetry and reward decision IDs must match exactly")

        evaluations = []
        for sequence, (decision, outcome, reward) in enumerate(normalized_records, 1):
            selected = decision["selected_action"]
            allowed = list(dict.fromkeys(decision["allowed_actions"]))
            alternatives = [action for action in allowed if action != selected]
            ranked = sorted(alternatives, key=lambda action: (-observed_action_counts[action], action))
            alternative_ranking = []
            for rank, action in enumerate(ranked, 1):
                observed_count = observed_action_counts[action]
                alternative_ranking.append({
                    "rank": rank,
                    "strategy_id": action,
                    "name": approved[action]["name"],
                    "validation_version": approved[action]["validation_version"],
                    "observed_in_same_session": observed_count,
                    "supporting_decision_ids": list(
                        observed_action_decisions.get(action, ())
                    ),
                    "evidence_status": (
                        "OBSERVED_IN_DIFFERENT_DECISION_CONTEXT"
                        if observed_count else "NOT_OBSERVED_IN_SESSION"
                    ),
                    "estimated_performance": None,
                })
            dimensions = copy.deepcopy(reward["dimensions"])
            importance_reasons = _important_reasons(outcome, dimensions, decision)
            evaluations.append({
                "sequence": sequence,
                "decision_id": decision["decision_id"],
                "timestamp": str(decision.get("timestamp") or "")[:64],
                "important": bool(importance_reasons),
                "importance_reasons": importance_reasons,
                "decision": {
                    "selected_action": selected,
                    "rule_default_action": decision.get("rule_default_action"),
                    "selector_type": decision.get("selector_type"),
                    "policy_version": decision.get("policy_version"),
                    "allowed_actions": allowed,
                    "confidence": decision.get("confidence"),
                },
                "observed_reward": {
                    "reward_version": reward.get("reward_version"),
                    "calibration_status": reward.get("calibration_status"),
                    "composite_reward": reward.get("composite_reward"),
                    "dimensions": dimensions,
                },
                "approved_alternative_ranking": {
                    "status": "EVIDENCE_AVAILABILITY_ONLY",
                    "method": "same-session-observation-count-then-strategy-id-v1",
                    "performance_ranking_available": False,
                    "alternatives": alternative_ranking,
                },
                "policy_assessment": _policy_assessment(decision, outcome, dimensions),
                "similar_session_comparison": {
                    "status": "DEFERRED_PHASE_14", "supporting_session_ids": [],
                },
                "counterfactual_estimate": {
                    "status": "DEFERRED_PHASE_14", "claim": None, "confidence": None,
                },
                "coverage_gap_assessment": {
                    "status": "DEFERRED_PHASE_15", "proposal_created": False,
                },
            })

        reconstructed = {
            "session_id": session_id,
            "protocol": protocol,
            "decision_count": len(evaluations),
            "first_decision_at": evaluations[0]["timestamp"],
            "last_decision_at": evaluations[-1]["timestamp"],
            "selected_strategy_sequence": [
                item["decision"]["selected_action"] for item in evaluations
            ],
            "important_decision_ids": [
                item["decision_id"] for item in evaluations if item["important"]
            ],
        }
        identity = json.dumps({
            "version": ANALYSIS_VERSION,
            "session": reconstructed,
            "decisions": decision_ids,
            "registry_version": registry_version,
            "aggregate_reward": aggregate,
            "evidence_digest": evidence_digest,
        }, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return {
            "analysis_version": ANALYSIS_VERSION,
            "analysis_id": "LA-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
            "status": "COMPLETE",
            "scope": "OFFLINE_RETROSPECTIVE",
            "session_id": session_id,
            "authority": {
                "read_only": True,
                "live_policy_mutation": False,
                "model_training": False,
                "strategy_activation": False,
                "infrastructure_authority": False,
            },
            "evidence": {
                "registry_version": registry_version,
                "telemetry_version": "strategy-telemetry-v1",
                "reward_version": "deception-reward-v1",
                "decision_ids": decision_ids,
                "input_sha256": evidence_digest,
                "raw_attacker_text_used": False,
            },
            "session_reconstruction": reconstructed,
            "decision_evaluations": evaluations,
            "session_observed_reward": {
                "calibration_status": session_reward.get("calibration_status"),
                "composite_reward": session_reward.get("composite_reward"),
                "aggregate_dimensions": aggregate,
            },
            "later_phase_boundaries": {
                "similar_session_retrieval": "PHASE_14",
                "counterfactual_estimation": "PHASE_14",
                "coverage_gap_detection": "PHASE_15",
                "proposal_creation": "PHASE_15",
                "live_policy_changes": "FORBIDDEN",
            },
        }
