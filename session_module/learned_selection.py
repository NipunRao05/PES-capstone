"""Fail-closed gate for bounded learned deception-strategy selection."""

from __future__ import annotations

import copy
import math
from typing import Any

from shadow_bandit import CONTEXT_VERSION, MODEL_VERSION

SELECTION_VERSION = "bounded-learned-selection-v1"
LEARNED_POLICY_VERSION = "bounded-learned-v1"
LEARNED_OPERATOR_MODE = "HYBRID_LEARNED_ADAPTIVE"
_APPROVED_ACTIONS = {"D0", "D1", "D2", "D3", "D4", "D6"}
_FORBIDDEN_FEATURES = {
    "query", "query_normalized", "fingerprint", "raw_sql", "source_ip",
    "client_ip", "prompt",
}
_FALLBACK_REASONS = {
    "operator_mode_rule", "model_unavailable", "invalid_model_output",
    "model_uncalibrated", "low_confidence", "model_agrees_with_rule",
    "validation_failed",
}


def _finite_probability(value: Any, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric") from exc
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{field} must be between zero and one")
    return number


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if number < 1 or number != value:
        raise ValueError(f"{field} must be a positive integer")
    return number


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc
    if number < 0 or number != value:
        raise ValueError(f"{field} must be a nonnegative integer")
    return number


def _rule_evidence(decision: Any) -> tuple[tuple[str, ...], str]:
    if not isinstance(decision, dict):
        raise ValueError("rule decision must be an object")
    allowed_raw = decision.get("allowed_actions")
    if not isinstance(allowed_raw, list):
        raise ValueError("allowed_actions must be a list")
    allowed = tuple(dict.fromkeys(
        str(item or "").strip().upper() for item in allowed_raw
    ))
    default = str(decision.get("rule_default_action") or "").strip().upper()
    selected = str(decision.get("strategy_id") or "").strip().upper()
    if (
        not allowed
        or any(action not in _APPROVED_ACTIONS for action in allowed)
        or default not in allowed
        or selected != default
        or str(decision.get("selector_type") or "").strip().lower() != "rule"
        or str(decision.get("policy_version") or "").strip() != "rule-v1"
        or _finite_probability(decision.get("confidence"), "confidence") != 1.0
    ):
        raise ValueError("invalid deterministic rule evidence")
    return allowed, default


def validate_executable_decision(
    decision: Any,
    *,
    expected_confidence_threshold: float | None = None,
    expected_minimum_updates: int | None = None,
) -> bool:
    """Validate either the exact rule fallback or a bounded learned choice."""
    if not isinstance(decision, dict):
        return False
    allowed_raw = decision.get("allowed_actions")
    if not isinstance(allowed_raw, list):
        return False
    allowed = tuple(dict.fromkeys(
        str(item or "").strip().upper() for item in allowed_raw
    ))
    selected = str(decision.get("strategy_id") or "").strip().upper()
    default = str(decision.get("rule_default_action") or "").strip().upper()
    selector = str(decision.get("selector_type") or "").strip().lower()
    policy_version = str(decision.get("policy_version") or "").strip()
    try:
        confidence = _finite_probability(decision.get("confidence"), "confidence")
    except ValueError:
        return False
    if (
        not allowed
        or any(action not in _APPROVED_ACTIONS for action in allowed)
        or selected not in allowed
        or default not in allowed
    ):
        return False
    if selector == "rule":
        return selected == default and policy_version == "rule-v1" and confidence == 1.0
    if selector != "learned" or policy_version != LEARNED_POLICY_VERSION:
        return False
    try:
        threshold = _finite_probability(
            decision.get("confidence_threshold"), "confidence_threshold"
        )
        minimum_updates = _positive_int(
            decision.get("minimum_training_updates"), "minimum_training_updates"
        )
        training_updates = _positive_int(
            decision.get("training_updates"), "training_updates"
        )
    except ValueError:
        return False
    if expected_confidence_threshold is not None and threshold != float(
        expected_confidence_threshold
    ):
        return False
    if expected_minimum_updates is not None and minimum_updates != int(
        expected_minimum_updates
    ):
        return False
    reward_profile = str(decision.get("reward_profile_version") or "").strip()
    return (
        str(decision.get("selection_version") or "") == SELECTION_VERSION
        and str(decision.get("selection_mode") or "") == LEARNED_OPERATOR_MODE
        and str(decision.get("selection_reason") or "") == "model_selected"
        and decision.get("learned_control") is True
        and str(decision.get("rule_policy_version") or "") == "rule-v1"
        and str(decision.get("model_version") or "") == MODEL_VERSION
        and str(decision.get("context_version") or "") == CONTEXT_VERSION
        and str(decision.get("calibration_status") or "") == "CALIBRATED"
        and 0 < len(reward_profile) <= 128
        and selected != default
        and confidence >= threshold
        and training_updates >= minimum_updates
    )


class BoundedLearnedSelector:
    """Permit learned control only with complete local safety evidence."""

    def __init__(self, confidence_threshold: float = 0.75, minimum_updates: int = 20):
        self.confidence_threshold = _finite_probability(
            confidence_threshold, "confidence_threshold"
        )
        self.minimum_updates = _positive_int(minimum_updates, "minimum_updates")

    @staticmethod
    def _fallback(rule_decision: dict, mode: str, reason: str) -> dict:
        fallback = copy.deepcopy(rule_decision)
        fallback.update({
            "selection_version": SELECTION_VERSION,
            "selection_mode": mode,
            "selection_reason": str(reason or "rule_fallback")[:64],
            "learned_control": False,
        })
        return fallback

    def select(
        self,
        rule_decision: dict,
        model_evaluation: Any,
        operator_mode: Any,
        *,
        expected_session_id: str = "",
    ) -> dict:
        allowed, default = _rule_evidence(rule_decision)
        mode = str(operator_mode or "RULE_ADAPTIVE").strip().upper()[:64]
        if mode != LEARNED_OPERATOR_MODE:
            return self._fallback(rule_decision, mode, "operator_mode_rule")
        if not isinstance(model_evaluation, dict):
            return self._fallback(rule_decision, mode, "model_unavailable")
        candidate = str(model_evaluation.get("model_recommended") or "").upper()
        model_allowed = model_evaluation.get("allowed_actions")
        scores = model_evaluation.get("scores")
        features = model_evaluation.get("context_features")
        reward_profile = str(
            model_evaluation.get("reward_profile_version") or ""
        ).strip()[:128]
        try:
            confidence = _finite_probability(
                model_evaluation.get("confidence"), "model confidence"
            )
            training_updates = _nonnegative_int(
                model_evaluation.get("training_updates"), "training_updates"
            )
        except ValueError:
            return self._fallback(rule_decision, mode, "invalid_model_output")
        if (
            model_evaluation.get("status") != "AVAILABLE"
            or model_evaluation.get("shadow_only") is not True
            or model_evaluation.get("controls_execution") is not False
            or str(model_evaluation.get("model_version") or "") != MODEL_VERSION
            or str(model_evaluation.get("context_version") or "") != CONTEXT_VERSION
            or str(model_evaluation.get("execution_source") or "") != "rule-v1"
            or (
                expected_session_id
                and str(model_evaluation.get("session_id") or "")
                != expected_session_id
            )
            or not isinstance(model_allowed, list)
            or set(model_allowed) != set(allowed)
            or str(model_evaluation.get("rule_selected") or "").upper() != default
            or str(model_evaluation.get("actual_execution") or "").upper() != default
            or candidate not in allowed
            or not isinstance(scores, dict)
            or set(scores) != set(allowed)
            or not isinstance(features, dict)
            or any(key in _FORBIDDEN_FEATURES for key in features)
        ):
            return self._fallback(rule_decision, mode, "invalid_model_output")
        numeric = tuple(scores.values()) + tuple(features.values())
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in numeric
        ) or any(not 0.0 <= float(value) <= 1.0 for value in features.values()):
            return self._fallback(rule_decision, mode, "invalid_model_output")
        ranked = sorted(allowed, key=lambda action: (-float(scores[action]), action))
        best = float(scores[ranked[0]])
        second = float(scores[ranked[1]]) if len(ranked) > 1 else best
        expected_confidence = 0.0 if len(ranked) < 2 else min(
            1.0, max(0.0, (best - second) / (1.0 + abs(best)))
        )
        if candidate != ranked[0] or abs(confidence - expected_confidence) > 1e-8:
            return self._fallback(rule_decision, mode, "invalid_model_output")
        if (
            model_evaluation.get("calibration_status") != "CALIBRATED"
            or not reward_profile
            or training_updates < self.minimum_updates
        ):
            return self._fallback(rule_decision, mode, "model_uncalibrated")
        if confidence < self.confidence_threshold:
            return self._fallback(rule_decision, mode, "low_confidence")
        if candidate == default:
            return self._fallback(rule_decision, mode, "model_agrees_with_rule")
        learned = {
            "strategy_id": candidate,
            "confidence": confidence,
            "selector_type": "learned",
            "policy_version": LEARNED_POLICY_VERSION,
            "allowed_actions": list(allowed),
            "rule_default_action": default,
            "selection_version": SELECTION_VERSION,
            "selection_mode": LEARNED_OPERATOR_MODE,
            "selection_reason": "model_selected",
            "learned_control": True,
            "rule_policy_version": "rule-v1",
            "model_version": MODEL_VERSION,
            "context_version": CONTEXT_VERSION,
            "training_updates": training_updates,
            "calibration_status": "CALIBRATED",
            "reward_profile_version": reward_profile,
            "confidence_threshold": self.confidence_threshold,
            "minimum_training_updates": self.minimum_updates,
        }
        if not validate_executable_decision(
            learned,
            expected_confidence_threshold=self.confidence_threshold,
            expected_minimum_updates=self.minimum_updates,
        ):
            return self._fallback(rule_decision, mode, "validation_failed")
        return learned

    def policy(self) -> dict:
        return {
            "selection_version": SELECTION_VERSION,
            "learned_policy_version": LEARNED_POLICY_VERSION,
            "learned_operator_mode": LEARNED_OPERATOR_MODE,
            "confidence_threshold": self.confidence_threshold,
            "minimum_training_updates": self.minimum_updates,
            "approved_actions": sorted(_APPROVED_ACTIONS),
            "fallback": "rule_default",
        }


def clean_selection_metadata(decision: Any) -> dict:
    """Return only bounded, validated fields suitable for telemetry."""
    if not isinstance(decision, dict) or decision.get("selection_version") is None:
        return {}
    selector = str(decision.get("selector_type") or "").lower()
    if selector == "learned":
        if not validate_executable_decision(decision):
            return {}
        fields = (
            "selection_version", "selection_mode", "selection_reason",
            "learned_control", "rule_policy_version", "model_version",
            "context_version", "training_updates", "calibration_status",
            "reward_profile_version", "confidence_threshold",
            "minimum_training_updates",
        )
        return {field: copy.deepcopy(decision[field]) for field in fields}
    mode = str(decision.get("selection_mode") or "").strip().upper()[:64]
    reason = str(decision.get("selection_reason") or "").strip()[:64]
    if (
        selector != "rule"
        or not validate_executable_decision(decision)
        or decision.get("selection_version") != SELECTION_VERSION
        or decision.get("learned_control") is not False
        or reason not in _FALLBACK_REASONS
    ):
        return {}
    return {
        "selection_version": SELECTION_VERSION,
        "selection_mode": mode,
        "selection_reason": reason,
        "learned_control": False,
    }
