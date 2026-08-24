"""Deterministic Phase 15 action-space gap detection and proposals.

This module is offline, read-only, and recommendation-only. It cannot review,
approve, activate, persist, deploy, or execute a strategy.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from typing import Any

try:
    from .similarity import SimilarSessionEvaluator, _distance, _validated_records
except ImportError:  # Direct script execution in the documented local container.
    from similarity import SimilarSessionEvaluator, _distance, _validated_records

GAP_DETECTION_VERSION = "action-space-gap-v1"
PROPOSAL_SCHEMA_VERSION = "strategy-gap-proposal-v1"

_SESSION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_KNOWN_THEME_FEATURES = {
    "bounded_catalog_query_count": "D1",
    "bounded_metadata_query_count": "D1",
    "bounded_backup_keyword_count": "D2",
    "bounded_credential_keyword_count": "D3",
    "bounded_sensitive_table_interest": "D4",
    "bounded_role_enumeration_count": "D5",
    "bounded_privilege_escalation_attempts": "D5",
    "bounded_destructive_query_count": "D6",
}
_MIN_RECURRING_HISTORY_SESSIONS = 3
_MIN_WEAK_STRATEGIES = 2
_HIGH_DIVERSITY_THRESHOLD = 0.8
_ACTIVE_THEME_THRESHOLD = 0.5


def _safe_session_id(value: Any) -> str:
    session_id = str(value or "").strip()
    if not _SESSION_ID.fullmatch(session_id):
        raise ValueError("historical exclusion contains an invalid session_id")
    return session_id


def _registry_index(registry: dict) -> dict[str, dict]:
    strategies = registry.get("strategies") if isinstance(registry, dict) else None
    if not isinstance(strategies, list):
        raise ValueError("validated strategy registry evidence is required")
    index: dict[str, dict] = {}
    for strategy in strategies:
        if not isinstance(strategy, dict):
            raise ValueError("strategy registry entries must be objects")
        strategy_id = str(strategy.get("strategy_id") or "").strip().upper()
        if not re.fullmatch(r"D[0-9]+", strategy_id) or strategy_id in index:
            raise ValueError("strategy registry entries are invalid")
        index[strategy_id] = {
            "strategy_id": strategy_id,
            "name": str(strategy.get("name") or "")[:128],
            "approval_status": str(strategy.get("approval_status") or "").upper()[:64],
        }
    return index


def _incomplete_bundle(bundle: dict) -> tuple[bool, str]:
    if not isinstance(bundle, dict):
        raise ValueError("historical session bundles must be objects")
    telemetry = bundle.get("telemetry")
    reward = bundle.get("reward")
    if not isinstance(telemetry, dict) or not isinstance(reward, dict):
        raise ValueError("historical telemetry and reward are required")
    session_id = _safe_session_id(telemetry.get("session_id"))
    return reward.get("status") != "COMPLETE", session_id


def _validate_external_exclusions(exclusions: Any) -> list[dict]:
    if exclusions is None:
        return []
    if not isinstance(exclusions, list) or len(exclusions) > 50:
        raise ValueError("historical exclusions must be a list of at most 50 entries")
    validated: list[dict] = []
    seen: set[str] = set()
    for item in exclusions:
        if not isinstance(item, dict):
            raise ValueError("historical exclusion entries must be objects")
        session_id = _safe_session_id(item.get("session_id"))
        reason = str(item.get("reason") or "").strip().upper()
        if reason not in {"INCOMPLETE_EVIDENCE", "UNAVAILABLE_EVIDENCE"}:
            raise ValueError("historical exclusion reason is unsupported")
        if session_id not in seen:
            seen.add(session_id)
            validated.append({"session_id": session_id, "reason": reason})
    return sorted(validated, key=lambda item: (item["session_id"], item["reason"]))


def _active_known_themes(features: dict, registry_index: dict[str, dict]) -> list[dict]:
    themes: dict[str, list[str]] = {}
    for feature, strategy_id in _KNOWN_THEME_FEATURES.items():
        value = features.get(feature, 0.0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("normalized behavior features must be finite numeric values")
        if value >= _ACTIVE_THEME_THRESHOLD:
            themes.setdefault(strategy_id, []).append(feature)
    return [
        {
            "strategy_id": strategy_id,
            "strategy_name": registry_index.get(strategy_id, {}).get("name", ""),
            "registry_status": registry_index.get(strategy_id, {}).get("approval_status", "ABSENT"),
            "behavior_features": sorted(feature_names),
        }
        for strategy_id, feature_names in sorted(themes.items())
    ]


def _unmodeled_pattern(record: dict, registry_index: dict[str, dict]) -> dict:
    features = record["context"]["features"]
    diversity = float(features.get("bounded_unique_query_family_count", 0.0))
    known_themes = _active_known_themes(features, registry_index)
    return {
        "signal": "RECURRING_UNMODELED_QUERY_FAMILIES",
        "coherent": diversity >= _HIGH_DIVERSITY_THRESHOLD and not known_themes,
        "bounded_unique_query_family_count": round(diversity, 9),
        "active_known_themes": known_themes,
        "feature_rule": (
            "bounded_unique_query_family_count>=0.8 and no recognized "
            "catalog/metadata/backup/credential/sensitive/privilege/destructive feature>=0.5"
        ),
    }


def _weak_outcome(record: dict) -> bool:
    reward = record["reward"]
    return (
        reward["engagement_queries"] <= 1
        and reward["new_tables"] == 0
        and reward["new_mitre_techniques"] == 0
        and reward["new_query_families"] == 0
        and reward["trap_interactions"] == 0
        and reward["protocol_errors"] == 0
        and reward["state_inconsistencies"] == 0
        and reward["safety_penalty"] == 0
    )


class ActionSpaceGapDetector:
    """Classify evidence and emit non-deployable proposals when justified."""

    def __init__(self, max_distance: float = 0.35):
        if isinstance(max_distance, bool):
            raise ValueError("max_distance must be numeric")
        try:
            distance = float(max_distance)
        except (TypeError, ValueError) as exc:
            raise ValueError("max_distance must be numeric") from exc
        if not math.isfinite(distance) or not 0 < distance <= 1:
            raise ValueError("max_distance must be in (0, 1]")
        self.max_distance = distance

    def analyze(
        self,
        target_telemetry: dict,
        target_reward: dict,
        historical_sessions: list[dict],
        registry: dict,
        historical_exclusions: list[dict] | None = None,
    ) -> dict:
        if not isinstance(historical_sessions, list) or len(historical_sessions) > 50:
            raise ValueError("historical_sessions must be a list of at most 50 bundles")
        exclusions = _validate_external_exclusions(historical_exclusions)
        excluded_ids = {item["session_id"] for item in exclusions}
        completed_history: list[dict] = []
        completed_ids: set[str] = set()
        for bundle in historical_sessions:
            incomplete, session_id = _incomplete_bundle(bundle)
            if session_id in completed_ids or session_id in excluded_ids:
                raise ValueError("duplicate historical session evidence is not allowed")
            if incomplete:
                exclusions.append({
                    "session_id": session_id, "reason": "INCOMPLETE_EVIDENCE"
                })
                excluded_ids.add(session_id)
                continue
            completed_ids.add(session_id)
            completed_history.append(bundle)
        exclusions.sort(key=lambda item: (item["session_id"], item["reason"]))

        counterfactual = SimilarSessionEvaluator(
            neighbor_limit=25, max_distance=self.max_distance
        ).analyze(target_telemetry, target_reward, completed_history, registry)
        registry_index = _registry_index(registry)
        _target_report, target_records = _validated_records(
            target_telemetry, target_reward, registry
        )
        history_records: list[dict] = []
        for bundle in completed_history:
            _history_report, records = _validated_records(
                bundle["telemetry"], bundle["reward"], registry
            )
            history_records.extend(records)

        decision_results: list[dict] = []
        proposals: list[dict] = []
        for target, phase14 in zip(target_records, counterfactual["decision_analyses"]):
            pattern = _unmodeled_pattern(target, registry_index)
            comparable: list[dict] = []
            for candidate in history_records:
                if candidate["context"]["protocol"] != target["context"]["protocol"]:
                    continue
                distance = _distance(target["context"]["vector"], candidate["context"]["vector"])
                if distance > self.max_distance:
                    continue
                if not _unmodeled_pattern(candidate, registry_index)["coherent"]:
                    continue
                comparable.append({
                    **candidate,
                    "distance": distance,
                    "similarity": 1.0 - distance,
                    "weak_outcome": _weak_outcome(candidate),
                })
            comparable.sort(key=lambda item: (
                item["distance"], item["session_id"], item["decision_id"]
            ))
            recurring_session_ids = sorted({item["session_id"] for item in comparable})
            weak_records = [item for item in comparable if item["weak_outcome"]]
            target_weak = _weak_outcome(target)
            weak_strategy_ids = sorted({
                item["selected_action"] for item in weak_records
            } | ({target["selected_action"]} if target_weak else set()))
            mapped = pattern["active_known_themes"]

            if mapped:
                classification = "NO_GAP_DETECTED"
                reason = (
                    "Observed behavior is represented by existing strategy metadata; "
                    "Phase 15 does not duplicate an existing capability."
                )
            elif not pattern["coherent"]:
                classification = "NO_GAP_DETECTED"
                reason = "No coherent unrepresented behavior signal met the deterministic gap rule."
            elif len(recurring_session_ids) < _MIN_RECURRING_HISTORY_SESSIONS:
                classification = "INSUFFICIENT_EVIDENCE"
                reason = (
                    "A possible unmodeled pattern exists, but fewer than three distinct "
                    "comparable completed historical sessions support it."
                )
            elif not target_weak:
                classification = "NO_GAP_DETECTED"
                reason = "The recurring unmodeled pattern lacks weak target-outcome evidence."
            elif len(weak_records) < _MIN_RECURRING_HISTORY_SESSIONS:
                classification = "NO_GAP_DETECTED"
                reason = "Comparable sessions do not repeatedly show weak safe outcomes."
            elif len(weak_strategy_ids) < _MIN_WEAK_STRATEGIES:
                classification = "INSUFFICIENT_EVIDENCE"
                reason = (
                    "Weak evidence exists for only one strategy; missing alternative evidence "
                    "alone cannot establish an action-space gap."
                )
            else:
                classification = "ACTION_SPACE_GAP"
                reason = (
                    "A high-diversity behavior pattern with no recognized strategy theme recurs "
                    "across completed similar sessions and has weak safe outcomes under multiple "
                    "existing strategies."
                )

            supporting_records = [target] + weak_records if classification == "ACTION_SPACE_GAP" else []
            supporting_session_ids = sorted({item["session_id"] for item in supporting_records})
            supporting_decision_ids = sorted({item["decision_id"] for item in supporting_records})
            phase14_alternatives = {
                item["strategy_id"]: item for item in phase14["counterfactual_estimates"]
            }
            considered_actions = sorted(set(target["allowed_actions"]) | set(weak_strategy_ids))
            strategy_analysis: list[dict] = []
            for action in considered_actions:
                selected_support = [
                    item for item in supporting_records if item["selected_action"] == action
                ]
                alternative = phase14_alternatives.get(action)
                metadata = registry_index.get(action, {})
                strategy_analysis.append({
                    "strategy_id": action,
                    "strategy_name": metadata.get("name", ""),
                    "registry_status": metadata.get("approval_status", "ABSENT"),
                    "weak_observation_count": len(selected_support),
                    "supporting_decision_ids": sorted(item["decision_id"] for item in selected_support),
                    "counterfactual_status": (
                        alternative.get("status") if alternative else
                        "OBSERVED_TARGET_SELECTION" if action == target["selected_action"]
                        else "NOT_EVALUATED"
                    ),
                })

            proposal = None
            if classification == "ACTION_SPACE_GAP":
                mean_similarity = sum(item["similarity"] for item in weak_records) / len(weak_records)
                support_factor = min(1.0, len(supporting_session_ids) / 5.0)
                strategy_factor = min(1.0, len(weak_strategy_ids) / 3.0)
                confidence = min(
                    0.69,
                    0.5 * support_factor + 0.3 * strategy_factor + 0.2 * mean_similarity,
                )
                proposal_basis = {
                    "schema_version": PROPOSAL_SCHEMA_VERSION,
                    "target_session_id": target["session_id"],
                    "target_decision_id": target["decision_id"],
                    "registry_version": counterfactual["evidence"]["registry_version"],
                    "counterfactual_analysis_id": counterfactual["analysis_id"],
                    "classification": classification,
                    "supporting_session_ids": supporting_session_ids,
                    "supporting_decision_ids": supporting_decision_ids,
                    "weak_strategy_ids": weak_strategy_ids,
                    "signal": pattern["signal"],
                }
                proposal_id = "P-" + hashlib.sha256(json.dumps(
                    proposal_basis, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")).hexdigest()[:24]
                proposal = {
                    "proposal_schema_version": PROPOSAL_SCHEMA_VERSION,
                    "proposal_id": proposal_id,
                    "status": "REQUIRES_REVIEW",
                    "proposal_type": "ACTION_SPACE_GAP",
                    "name": "UNMODELED_RECURRING_BEHAVIOR_LURE",
                    "trigger_context": {
                        "context_version": target["context"]["context_version"],
                        "protocol": target["context"]["protocol"],
                        "context_group": target["context"]["context_group"],
                        "signal": pattern["signal"],
                        "feature_rule": pattern["feature_rule"],
                    },
                    "reason": reason,
                    "supporting_session_ids": supporting_session_ids,
                    "supporting_decision_ids": supporting_decision_ids,
                    "observed_behavior": {
                        "signal": pattern["signal"],
                        "target_feature_evidence": {
                            "bounded_unique_query_family_count": pattern[
                                "bounded_unique_query_family_count"
                            ],
                            "active_known_themes": [],
                        },
                        "comparable_completed_session_count": len(recurring_session_ids),
                        "weak_completed_history_count": len(weak_records),
                        "weak_strategy_ids": weak_strategy_ids,
                    },
                    "existing_strategy_analysis": strategy_analysis,
                    "estimated_benefit": None,
                    "confidence": round(confidence, 9),
                    "confidence_label": "MEDIUM" if confidence >= 0.4 else "LOW",
                    "confidence_basis": (
                        "bounded completed-session quantity, normalized-context similarity, "
                        "and weak-strategy coverage; capped while reward weights are uncalibrated"
                    ),
                    "proposed_capability": {
                        "objective": (
                            "Instrument recurring unmodeled query-family behavior using "
                            "synthetic-only validation-gated deception."
                        ),
                        "suggested_assets": [
                            "synthetic metadata bundle for the evidenced unmodeled behavior family"
                        ],
                        "suggested_behavior": [
                            "record interactions under existing deterministic protocol and safety rules"
                        ],
                    },
                    "risks": [
                        "classifier-level behavior may combine unrelated query families",
                        "observational evidence does not establish causal benefit",
                        "all assets require later human review and deterministic validation",
                    ],
                    "resource_cost": "unknown",
                    "authority": {
                        "read_only": True,
                        "deployable": False,
                        "requires_human_review": True,
                        "registry_mutation": False,
                        "policy_mutation": False,
                        "live_execution": False,
                    },
                }
                proposals.append(proposal)

            decision_results.append({
                "decision_id": target["decision_id"],
                "classification": classification,
                "reason": reason,
                "behavior_gap_signal": pattern,
                "recurring_completed_history_session_ids": recurring_session_ids,
                "weak_strategy_ids": weak_strategy_ids,
                "existing_strategy_analysis": strategy_analysis,
                "proposal": proposal,
            })

        classifications = {item["classification"] for item in decision_results}
        if "ACTION_SPACE_GAP" in classifications:
            overall = "ACTION_SPACE_GAP"
        elif "INSUFFICIENT_EVIDENCE" in classifications:
            overall = "INSUFFICIENT_EVIDENCE"
        else:
            overall = "NO_GAP_DETECTED"
        identity = {
            "version": GAP_DETECTION_VERSION,
            "counterfactual_analysis_id": counterfactual["analysis_id"],
            "registry_version": counterfactual["evidence"]["registry_version"],
            "exclusions": exclusions,
            "decision_results": decision_results,
        }
        analysis_id = "GD-" + hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")).hexdigest()[:24]
        return {
            "gap_detection_version": GAP_DETECTION_VERSION,
            "analysis_id": analysis_id,
            "status": "COMPLETE",
            "classification": overall,
            "session_id": counterfactual["session_id"],
            "authority": {
                "read_only": True,
                "recommendation_only": True,
                "deployable": False,
                "requires_human_review": True,
                "registry_mutation": False,
                "policy_mutation": False,
                "rule_mutation": False,
                "strategy_activation": False,
                "live_response_generation": False,
                "infrastructure_authority": False,
            },
            "evidence": {
                "counterfactual_analysis_id": counterfactual["analysis_id"],
                "registry_version": counterfactual["evidence"]["registry_version"],
                "completed_historical_session_ids": counterfactual["evidence"][
                    "historical_session_ids"
                ],
                "historical_exclusions": copy.deepcopy(exclusions),
                "raw_attacker_text_used": False,
                "llm_used": False,
            },
            "decision_results": decision_results,
            "proposals": proposals,
            "phase_16_boundary": {
                "review_workflow": "NOT_IMPLEMENTED",
                "review_queue_write": False,
                "review_decision": None,
                "approval_state_change": False,
            },
        }
