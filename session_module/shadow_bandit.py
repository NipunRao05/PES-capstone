"""Deterministic LinUCB recommendations for shadow-only strategy evaluation."""

from __future__ import annotations

import hashlib
import json
import math
import threading
from typing import Any

MODEL_VERSION = "linucb-shadow-v1"
CONTEXT_VERSION = "bandit-context-v1"
_APPROVED_ACTIONS = ("D0", "D1", "D2", "D3", "D4", "D6")
_FORBIDDEN_INPUTS = {
    "query", "query_normalized", "fingerprint", "raw_sql", "source_ip",
    "client_ip", "prompt",
}
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


def _dot(left: list[float], right: list[float]) -> float:
    return sum(a * b for a, b in zip(left, right))


def _matvec(matrix: list[list[float]], vector: list[float]) -> list[float]:
    return [_dot(row, vector) for row in matrix]


def _finite(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{name} must be finite and nonnegative")
    return number


def _saturate(value: Any, name: str) -> float:
    number = _finite(value, name)
    return number / (1.0 + number)


class ContextEncoder:
    """Convert minimized structured evidence into a stable bounded vector."""

    feature_names = (
        "bias", "protocol_mysql", "protocol_postgres", "risk_score",
        "mitre_stage_rank",
        *tuple(f"bounded_{name}" for name in _COUNT_FEATURES),
        *tuple(f"current_strategy_{action}" for action in _APPROVED_ACTIONS),
    )

    @classmethod
    def encode(cls, snapshot: dict) -> tuple[list[float], dict[str, float]]:
        if not isinstance(snapshot, dict):
            raise ValueError("snapshot must be an object")
        states = (
            snapshot.get("session_state") or {},
            snapshot.get("behavior_state") or {},
            snapshot.get("mitre_state") or {},
        )
        if any(not isinstance(state, dict) for state in states):
            raise ValueError("structured states must be objects")
        if any(key in _FORBIDDEN_INPUTS for state in states for key in state):
            raise ValueError("raw or identifying input is forbidden")
        session, behavior, mitre = states
        protocol = str(session.get("protocol") or behavior.get("protocol") or "").lower()
        if protocol == "postgresql":
            protocol = "postgres"
        if protocol not in {"mysql", "postgres"}:
            raise ValueError("supported protocol is required")
        risk = _finite(behavior.get("risk_score", 0.0), "risk_score")
        if risk > 1.0:
            raise ValueError("normalized risk_score cannot exceed one")
        stage = str(
            behavior.get("mitre_stage") or mitre.get("phase") or ""
        ).strip().lower()[:64]
        current = str(
            behavior.get("current_strategy") or session.get("strategy_id") or "D0"
        ).strip().upper()
        session_id = str(session.get("session_id") or "").strip()[:256]
        if not session_id:
            raise ValueError("session_id is required")
        if current not in _APPROVED_ACTIONS:
            raise ValueError("current strategy must be approved")
        values = [
            1.0,
            1.0 if protocol == "mysql" else 0.0,
            1.0 if protocol == "postgres" else 0.0,
            risk,
            _STAGE_ORDER.get(stage, 0) / max(_STAGE_ORDER.values()),
        ]
        values.extend(
            _saturate(behavior.get(name, 0), name) for name in _COUNT_FEATURES
        )
        values.extend(1.0 if current == action else 0.0 for action in _APPROVED_ACTIONS)
        features = {
            name: round(value, 9) for name, value in zip(cls.feature_names, values)
        }
        return values, features


class ShadowLinUCB:
    """Disjoint LinUCB that can recommend but has no execution authority."""

    def __init__(self, alpha: float = 0.5):
        if isinstance(alpha, bool) or not math.isfinite(float(alpha)) or alpha < 0:
            raise ValueError("alpha must be finite and nonnegative")
        self.alpha = float(alpha)
        self.dimension = len(ContextEncoder.feature_names)
        self._inverse = {
            action: [
                [1.0 if row == column else 0.0 for column in range(self.dimension)]
                for row in range(self.dimension)
            ]
            for action in _APPROVED_ACTIONS
        }
        self._b = {action: [0.0] * self.dimension for action in _APPROVED_ACTIONS}
        self._pulls = {action: 0 for action in _APPROVED_ACTIONS}
        self._recommendations = 0
        self._updates = 0
        self._lock = threading.RLock()

    @staticmethod
    def _allowed(actions: Any, rule_default: Any) -> tuple[tuple[str, ...], str]:
        if not isinstance(actions, list):
            raise ValueError("allowed_actions must be a list")
        allowed = tuple(dict.fromkeys(
            str(item or "").strip().upper() for item in actions
        ))
        default = str(rule_default or "").strip().upper()
        if (
            not allowed
            or any(action not in _APPROVED_ACTIONS for action in allowed)
            or default not in allowed
        ):
            raise ValueError("action space must be approved and contain its default")
        return allowed, default

    def recommend(self, snapshot: dict, actions: list[str], rule_default: str) -> dict:
        allowed, default = self._allowed(actions, rule_default)
        vector, features = ContextEncoder.encode(snapshot)
        with self._lock:
            scores = {}
            for action in allowed:
                inverse = self._inverse[action]
                theta = _matvec(inverse, self._b[action])
                transformed = _matvec(inverse, vector)
                variance = max(0.0, _dot(vector, transformed))
                score = _dot(theta, vector) + self.alpha * math.sqrt(variance)
                scores[action] = round(score, 9)
            ranked = sorted(allowed, key=lambda action: (-scores[action], action))
            recommended = ranked[0]
            best = scores[recommended]
            second = scores[ranked[1]] if len(ranked) > 1 else best
            confidence = 0.0 if len(ranked) < 2 else min(
                1.0, max(0.0, (best - second) / (1.0 + abs(best)))
            )
            self._recommendations += 1
            model_pulls = dict(self._pulls)
        session_id = str(
            (snapshot.get("session_state") or {}).get("session_id") or ""
        ).strip()[:256]
        identity = json.dumps({
            "session_id": session_id,
            "query_count": snapshot.get("query_count", 0),
            "features": features,
            "allowed": allowed,
            "rule_default": default,
            "recommended": recommended,
            "model_version": MODEL_VERSION,
        }, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return {
            "shadow_id": "SH-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
            "status": "AVAILABLE",
            "shadow_only": True,
            "controls_execution": False,
            "model_version": MODEL_VERSION,
            "context_version": CONTEXT_VERSION,
            "session_id": session_id,
            "timestamp": str(snapshot.get("observed_at") or "")[:64],
            "allowed_actions": list(allowed),
            "rule_selected": default,
            "model_recommended": recommended,
            "actual_execution": default,
            "execution_source": "rule-v1",
            "agreement": recommended == default,
            "confidence": round(confidence, 9),
            "scores": scores,
            "context_features": features,
            "training_updates": sum(model_pulls.values()),
        }

    def update(
        self,
        action: str,
        snapshot: dict,
        reward: float,
        *,
        calibration_status: str,
        reward_profile_version: str,
    ) -> None:
        action = str(action or "").strip().upper()
        if action not in _APPROVED_ACTIONS:
            raise ValueError("only approved actions can be updated")
        if calibration_status != "CALIBRATED" or not str(reward_profile_version).strip():
            raise ValueError("a versioned calibrated scalar reward is required")
        if isinstance(reward, bool):
            raise ValueError("reward must be numeric")
        reward = float(reward)
        if not math.isfinite(reward) or not -1.0 <= reward <= 1.0:
            raise ValueError("reward must be finite and between -1 and 1")
        vector, _features = ContextEncoder.encode(snapshot)
        with self._lock:
            inverse = self._inverse[action]
            transformed = _matvec(inverse, vector)
            denominator = 1.0 + _dot(vector, transformed)
            for row in range(self.dimension):
                for column in range(self.dimension):
                    inverse[row][column] -= (
                        transformed[row] * transformed[column] / denominator
                    )
            for index, value in enumerate(vector):
                self._b[action][index] += reward * value
            self._pulls[action] += 1
            self._updates += 1

    def unavailable(self, snapshot: dict, rule_default: Any, reason: str) -> dict:
        session_id = str(
            (snapshot.get("session_state") or {}).get("session_id") or ""
        ).strip()[:256]
        default = str(rule_default or "").strip().upper()
        return {
            "shadow_id": "",
            "status": "UNAVAILABLE",
            "shadow_only": True,
            "controls_execution": False,
            "model_version": MODEL_VERSION,
            "context_version": CONTEXT_VERSION,
            "session_id": session_id,
            "timestamp": str(snapshot.get("observed_at") or "")[:64],
            "allowed_actions": [],
            "rule_selected": default,
            "model_recommended": "",
            "actual_execution": default,
            "execution_source": "rule-v1",
            "agreement": False,
            "confidence": 0.0,
            "scores": {},
            "context_features": {},
            "training_updates": self.stats()["updates"],
            "reason": str(reason or "model_unavailable")[:64],
        }

    def stats(self) -> dict:
        with self._lock:
            return {
                "model_version": MODEL_VERSION,
                "context_version": CONTEXT_VERSION,
                "algorithm": "disjoint-linucb",
                "shadow_only": True,
                "controls_execution": False,
                "alpha": self.alpha,
                "dimension": self.dimension,
                "recommendations": self._recommendations,
                "updates": self._updates,
                "pulls": dict(self._pulls),
                "calibrated_reward_required": True,
            }
