"""Bounded decision/outcome telemetry for asynchronous strategy selection.

Only minimized structured state is retained. Persistence, rewards, and learned
selection intentionally belong to later phases.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

TELEMETRY_VERSION = "strategy-telemetry-v1"
_APPROVED_STRATEGIES = {"D0", "D1", "D2", "D3", "D4", "D6"}
_FORBIDDEN_INPUTS = {
    "query", "query_normalized", "fingerprint", "raw_sql", "source_ip",
    "client_ip", "prompt",
}
_SHADOW_MODEL_VERSION = "linucb-shadow-v1"
_SHADOW_CONTEXT_VERSION = "bandit-context-v1"
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


def _nonnegative_number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) and number >= 0 else default


def _nonnegative_int(value: Any) -> int:
    return int(_nonnegative_number(value, 0.0))


def _stage(value: Any) -> str:
    return str(value or "").strip().lower()[:64]


class StrategyTelemetryStore:
    """Thread-safe bounded linkage between accepted decisions and outcomes."""

    def __init__(self, max_records: int = 20_000):
        self.max_records = min(max(int(max_records), 1), 100_000)
        self._decisions: OrderedDict[str, dict] = OrderedDict()
        self._outcomes: dict[str, dict] = {}
        self._baselines: dict[str, dict] = {}
        self._session_index: dict[str, list[str]] = {}
        self._sequence: dict[str, int] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _state_before(snapshot: dict) -> dict:
        return {
            "session_state": copy.deepcopy(snapshot.get("session_state") or {}),
            "behavior_state": copy.deepcopy(snapshot.get("behavior_state") or {}),
            "mitre_state": copy.deepcopy(snapshot.get("mitre_state") or {}),
        }

    @staticmethod
    def _baseline(snapshot: dict) -> dict:
        behavior = snapshot.get("behavior_state") or {}
        state = snapshot.get("session_state") or {}
        mitre = snapshot.get("mitre_state") or {}
        return {
            "query_count": _nonnegative_int(snapshot.get("query_count")),
            "session_duration_seconds": _nonnegative_number(
                behavior.get("session_duration_seconds")
            ),
            "unique_query_family_count": _nonnegative_int(
                behavior.get("unique_query_family_count")
            ),
            "unique_table_count": _nonnegative_int(
                behavior.get("unique_table_count")
            ),
            "mitre_technique_count": _nonnegative_int(
                behavior.get("mitre_technique_count")
            ),
            "trap_trigger_count": _nonnegative_int(
                behavior.get("trap_trigger_count")
            ),
            "errors": _nonnegative_int(snapshot.get("failed_query_count"))
            + _nonnegative_int(behavior.get("failed_auth_count")),
            "protocol_errors": _nonnegative_int(
                snapshot.get("unverified_query_count")
            ),
            "state_inconsistencies": _nonnegative_int(
                snapshot.get("state_inconsistency_count")
            ),
            "mitre_stage": _stage(
                behavior.get("mitre_stage") or mitre.get("phase")
            ),
            "closed_at": str(snapshot.get("closed_at") or "")[:64],
            "discovered_object_count": len(state.get("discovered_objects") or []),
        }

    @staticmethod
    def _cost(value: Any) -> float:
        return round(_nonnegative_number(value), 6)

    def record_decision(
        self,
        snapshot: dict,
        response: dict,
        *,
        latency_ms: float = 0.0,
        cpu_cost_ms: float = 0.0,
        memory_cost_bytes: int = 0,
        shadow_evaluation: dict | None = None,
    ) -> dict | None:
        """Record one accepted rule decision and initialize its linked outcome."""
        if not isinstance(snapshot, dict) or not isinstance(response, dict):
            return None
        session_state = snapshot.get("session_state") or {}
        session_id = str(session_state.get("session_id") or "").strip()[:256]
        selected = str(response.get("strategy_id") or "").strip().upper()
        default = str(response.get("rule_default_action") or "").strip().upper()
        selector = str(response.get("selector_type") or "").strip().lower()
        policy_version = str(response.get("policy_version") or "").strip()[:128]
        allowed_raw = response.get("allowed_actions")
        if not isinstance(allowed_raw, list):
            return None
        allowed = tuple(dict.fromkeys(
            str(item or "").strip().upper() for item in allowed_raw
        ))
        confidence = response.get("confidence")
        if (
            not session_id
            or selected not in _APPROVED_STRATEGIES
            or default not in _APPROVED_STRATEGIES
            or selected != default
            or selected not in allowed
            or default not in allowed
            or any(item not in _APPROVED_STRATEGIES for item in allowed)
            or selector != "rule"
            or policy_version != "rule-v1"
            or isinstance(confidence, bool)
            or _nonnegative_number(confidence, -1.0) != 1.0
        ):
            return None

        state_before = self._state_before(snapshot)
        baseline = self._baseline(snapshot)
        timestamp = str(snapshot.get("observed_at") or "").strip()[:64]
        if not timestamp:
            timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        with self._lock:
            sequence = self._sequence.get(session_id, 0) + 1
            self._sequence[session_id] = sequence
            identity = json.dumps(
                {
                    "session_id": session_id,
                    "sequence": sequence,
                    "timestamp": timestamp,
                    "selected": selected,
                    "state_before": state_before,
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            decision_id = "SD-" + hashlib.sha256(identity).hexdigest()[:24]
            decision = {
                "telemetry_version": TELEMETRY_VERSION,
                "decision_id": decision_id,
                "session_id": session_id,
                "timestamp": timestamp,
                "state_before": state_before,
                "allowed_actions": list(allowed),
                "rule_default_action": default,
                "selected_action": selected,
                "selector_type": selector,
                "confidence": 1.0,
                "policy_version": policy_version,
            }
            cleaned_shadow = self._clean_shadow(
                shadow_evaluation, session_id, selected, allowed
            )
            if cleaned_shadow is not None:
                decision["shadow_evaluation"] = cleaned_shadow
            outcome = {
                "telemetry_version": TELEMETRY_VERSION,
                "decision_id": decision_id,
                "session_id": session_id,
                "queries_after_decision": 0,
                "session_duration_after_decision": 0.0,
                "new_query_families": 0,
                "new_tables_accessed": 0,
                "new_MITRE_techniques": 0,
                "trap_interactions": 0,
                "attacker_progression": {
                    "from_stage": baseline["mitre_stage"],
                    "to_stage": baseline["mitre_stage"],
                    "advanced": False,
                },
                "disconnect_time": baseline["closed_at"],
                "errors": 0,
                "protocol_errors": 0,
                "state_inconsistencies": 0,
                "latency": self._cost(latency_ms),
                "CPU_cost": self._cost(cpu_cost_ms),
                "memory_cost": _nonnegative_int(memory_cost_bytes),
                "measurement_units": {
                    "latency": "milliseconds",
                    "CPU_cost": "process_milliseconds",
                    "memory_cost": "serialized_bytes",
                },
                "final": bool(snapshot.get("closed")),
            }
            self._decisions[decision_id] = decision
            self._outcomes[decision_id] = outcome
            self._baselines[decision_id] = baseline
            self._session_index.setdefault(session_id, []).append(decision_id)
            self._evict_if_needed()
            return copy.deepcopy(decision)

    @staticmethod
    def _clean_shadow(
        shadow: dict | None,
        session_id: str,
        selected: str,
        allowed: tuple[str, ...],
    ) -> dict | None:
        """Accept shadow metadata only when it provably cannot alter execution."""
        if not isinstance(shadow, dict):
            return None
        status = str(shadow.get("status") or "").strip().upper()
        if (
            status not in {"AVAILABLE", "UNAVAILABLE"}
            or shadow.get("shadow_only") is not True
            or shadow.get("controls_execution") is not False
            or str(shadow.get("session_id") or "") != session_id
            or str(shadow.get("rule_selected") or "").upper() != selected
            or str(shadow.get("actual_execution") or "").upper() != selected
            or str(shadow.get("execution_source") or "") != "rule-v1"
        ):
            return None
        cleaned = copy.deepcopy(shadow)
        if (
            str(shadow.get("model_version") or "") != _SHADOW_MODEL_VERSION
            or str(shadow.get("context_version") or "") != _SHADOW_CONTEXT_VERSION
        ):
            return None
        if status == "UNAVAILABLE":
            if str(shadow.get("model_recommended") or ""):
                return None
            return cleaned
        model_action = str(shadow.get("model_recommended") or "").upper()
        shadow_allowed = shadow.get("allowed_actions")
        scores = shadow.get("scores")
        features = shadow.get("context_features")
        confidence = shadow.get("confidence")
        training_updates = shadow.get("training_updates")
        if (
            not str(shadow.get("shadow_id") or "").startswith("SH-")
            or not isinstance(shadow_allowed, list)
            or set(shadow_allowed) != set(allowed)
            or model_action not in allowed
            or shadow.get("agreement") is not (model_action == selected)
            or not isinstance(scores, dict)
            or set(scores) != set(allowed)
            or not isinstance(features, dict)
            or any(key in _FORBIDDEN_INPUTS for key in features)
            or isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
            or isinstance(training_updates, bool)
            or not isinstance(training_updates, int)
            or training_updates < 0
        ):
            return None
        numeric = tuple(scores.values()) + tuple(features.values())
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in numeric
        ):
            return None
        if any(not 0.0 <= float(value) <= 1.0 for value in features.values()):
            return None
        return cleaned

    def _evict_if_needed(self) -> None:
        while len(self._decisions) > self.max_records:
            decision_id, decision = self._decisions.popitem(last=False)
            self._outcomes.pop(decision_id, None)
            self._baselines.pop(decision_id, None)
            session_id = decision["session_id"]
            ids = self._session_index.get(session_id, [])
            self._session_index[session_id] = [item for item in ids if item != decision_id]
            if not self._session_index[session_id]:
                self._session_index.pop(session_id, None)

    def observe(self, snapshot: dict) -> int:
        """Update all decisions for a session from a later structured snapshot."""
        if not isinstance(snapshot, dict):
            return 0
        session_id = str(
            (snapshot.get("session_state") or {}).get("session_id") or ""
        ).strip()[:256]
        if not session_id:
            return 0
        current = self._baseline(snapshot)
        current_stage = current["mitre_stage"]
        with self._lock:
            decision_ids = tuple(self._session_index.get(session_id, ()))
            for decision_id in decision_ids:
                baseline = self._baselines.get(decision_id)
                outcome = self._outcomes.get(decision_id)
                if baseline is None or outcome is None:
                    continue
                outcome["queries_after_decision"] = max(
                    0, current["query_count"] - baseline["query_count"]
                )
                outcome["session_duration_after_decision"] = round(max(
                    0.0,
                    current["session_duration_seconds"]
                    - baseline["session_duration_seconds"],
                ), 6)
                outcome["new_query_families"] = max(
                    0,
                    current["unique_query_family_count"]
                    - baseline["unique_query_family_count"],
                )
                outcome["new_tables_accessed"] = max(
                    0,
                    current["unique_table_count"]
                    - baseline["unique_table_count"],
                )
                outcome["new_MITRE_techniques"] = max(
                    0,
                    current["mitre_technique_count"]
                    - baseline["mitre_technique_count"],
                )
                outcome["trap_interactions"] = max(
                    0,
                    current["trap_trigger_count"]
                    - baseline["trap_trigger_count"],
                )
                outcome["errors"] = max(0, current["errors"] - baseline["errors"])
                outcome["protocol_errors"] = max(
                    0,
                    current["protocol_errors"] - baseline["protocol_errors"],
                )
                outcome["state_inconsistencies"] = max(
                    0,
                    current["state_inconsistencies"]
                    - baseline["state_inconsistencies"],
                )
                from_stage = baseline["mitre_stage"]
                outcome["attacker_progression"] = {
                    "from_stage": from_stage,
                    "to_stage": current_stage,
                    "advanced": _STAGE_ORDER.get(current_stage, 0)
                    > _STAGE_ORDER.get(from_stage, 0),
                }
                outcome["disconnect_time"] = str(snapshot.get("closed_at") or "")[:64]
                outcome["final"] = bool(snapshot.get("closed"))
            return len(decision_ids)

    def get(self, decision_id: str) -> dict | None:
        with self._lock:
            decision = self._decisions.get(decision_id)
            outcome = self._outcomes.get(decision_id)
            if decision is None or outcome is None:
                return None
            return {
                "decision": copy.deepcopy(decision),
                "outcome": copy.deepcopy(outcome),
            }

    def session(self, session_id: str) -> dict:
        with self._lock:
            decision_ids = tuple(self._session_index.get(session_id, ()))
            return {
                "session_id": session_id,
                "records": [self.get(item) for item in decision_ids],
            }

    def list(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 250))
        with self._lock:
            ids = list(self._decisions.keys())[-limit:]
            ids.reverse()
            return [self.get(item) for item in ids]
