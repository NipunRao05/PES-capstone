"""Authoritative per-session state projected only from confirmed proxy outcomes.

The SQL engines remain the source of truth. This module never executes SQL and
never treats raw query intent as a successful database mutation.
"""

from __future__ import annotations

import copy
import json
import math
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from behavior_state import BehaviorStateStore
from experiment_assignment import ExperimentAssignmentController, normalize_protocol
from learned_selection import BoundedLearnedSelector, validate_executable_decision
from reward_model import DeceptionRewardModel
from shadow_bandit import ShadowLinUCB
from strategy_telemetry import StrategyTelemetryStore

_RELATION = r'([A-Za-z_][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$]*)?)'
_TRAP_TABLES = {
    "api_keys_backup", "salary_executives", "prod_credentials",
    "admin_tokens", "backup_passwords",
}
_MAX_SQL_CHARS = 65536
_MAX_METADATA_CHARS = 256
_MAX_OBJECTS_PER_SET = 512
_APPROVED_STRATEGY_IDS = {"D0", "D1", "D2", "D3", "D4", "D6"}
_STATE_SET_FIELDS = (
    "permissions", "visible_databases", "visible_tables", "visible_columns",
    "created_objects", "modified_objects", "dropped_objects",
    "discovered_objects", "triggered_traps",
)


def _bounded_experiment_identity(value) -> str:
    return str(value or "").replace("\x00", "").strip()[:512]


def _clean_identifier(value: str) -> str:
    return re.sub(r'["' + "'" + r'\x60\s]', "", value or "").lower().strip(".")


def _transaction_state(value: str) -> str:
    value = (value or "").strip().lower()
    if value in {"in_transaction", "failed_transaction"}:
        return value
    return "idle"


def _extract_relations(sql: str) -> set[str]:
    found: set[str] = set()
    patterns = [
        rf"\bcreate\s+(?:temporary\s+)?table\s+(?:if\s+not\s+exists\s+)?{_RELATION}",
        rf"\bdrop\s+table\s+(?:if\s+exists\s+)?{_RELATION}",
        rf"\binsert\s+into\s+{_RELATION}",
        rf"\bupdate\s+{_RELATION}",
        rf"\bdelete\s+from\s+{_RELATION}",
        rf"\b(?:alter|truncate)\s+table\s+{_RELATION}",
    ]
    if re.match(r"^(?:select|with|delete)\b", sql.strip(), re.I):
        patterns.extend((rf"\bfrom\s+{_RELATION}", rf"\bjoin\s+{_RELATION}"))
    for pattern in patterns:
        found.update(_clean_identifier(match) for match in re.findall(pattern, sql, re.I))
    return {item for item in found if item}


def _first_relation(sql: str, operation: str) -> str:
    patterns = {
        "create": rf"\bcreate\s+(?:temporary\s+)?table\s+(?:if\s+not\s+exists\s+)?{_RELATION}",
        "drop": rf"\bdrop\s+table\s+(?:if\s+exists\s+)?{_RELATION}",
        "insert": rf"\binsert\s+into\s+{_RELATION}",
        "update": rf"\bupdate\s+{_RELATION}",
        "delete": rf"\bdelete\s+from\s+{_RELATION}",
        "alter": rf"\b(?:alter|truncate)\s+table\s+{_RELATION}",
    }
    match = re.search(patterns[operation], sql, re.I)
    return _clean_identifier(match.group(1)) if match else ""


def _extract_create_columns(sql: str, relation: str) -> set[str]:
    if not relation:
        return set()
    match = re.search(r"\bcreate\s+(?:temporary\s+)?table\b[^()]*\((.*)\)", sql, re.I | re.S)
    if not match:
        return set()
    columns: set[str] = set()
    for item in match.group(1).split(","):
        token = item.strip().split()
        if not token:
            continue
        name = _clean_identifier(token[0])
        if name and name not in {"primary", "foreign", "unique", "constraint", "check"}:
            columns.add(f"{relation}.{name}")
    return columns


@dataclass
class AuthoritativeSessionState:
    session_id: str
    deceptive_principal_id: str = ""
    principal_origin: str = ""
    creator_session_id: str = ""
    is_return_session: bool = False
    protocol: str = ""
    persona_id: str = "deterministic-baseline"
    strategy_id: str = "D0"
    schema_version: int = 1
    database: str = ""
    user: str = ""
    role: str = ""
    permissions: set[str] = field(default_factory=set)
    transaction_state: str = "idle"
    visible_databases: set[str] = field(default_factory=set)
    visible_tables: set[str] = field(default_factory=set)
    visible_columns: set[str] = field(default_factory=set)
    created_objects: set[str] = field(default_factory=set)
    modified_objects: set[str] = field(default_factory=set)
    dropped_objects: set[str] = field(default_factory=set)
    discovered_objects: set[str] = field(default_factory=set)
    triggered_traps: set[str] = field(default_factory=set)
    mitre_stage: str = ""
    risk_score: float = 0.0
    query_count: int = 0
    session_depth: int = 0
    strategy_history: list[str] = field(default_factory=lambda: ["D0"])
    next_strategy_id: str = ""
    next_strategy_ready: bool = False
    next_strategy_confidence: float = 0.0
    next_strategy_selector_type: str = ""
    next_strategy_policy_version: str = ""
    next_strategy_query_count: int = 0
    next_strategy_updated_at: str = ""
    outcome_verified_count: int = 0
    unverified_query_count: int = 0
    failed_query_count: int = 0
    database_authority: str = ""
    last_query_fingerprint: str = ""
    last_error_code: str = ""
    started_at: str = ""
    updated_at: str = ""
    closed: bool = False
    closed_at: str = ""
    expected_query_count: int = 0
    experiment_id: str = ""
    experiment_arm: str = ""
    experiment_mode: str = ""
    experiment_assignment_version: str = ""
    experiment_cohort_hmac: str = ""
    world_revision: int = 0
    experiment_persisted: bool = False

    def to_dict(self) -> dict:
        payload = {}
        for name, value in self.__dict__.items():
            payload[name] = sorted(value) if isinstance(value, set) else value
        return payload


class AuthoritativeStateStore:
    """Thread-safe bounded state projection; persistence is intentionally Phase 24."""

    def __init__(
        self,
        max_sessions: int = 5000,
        *,
        shadow_bandit: ShadowLinUCB | None = None,
        learned_confidence_threshold: float = 0.75,
        learned_minimum_updates: int = 20,
        experiment_controller: ExperimentAssignmentController | None = None,
    ):
        self.max_sessions = min(max(1, max_sessions), 100_000)
        self._states: dict[str, AuthoritativeSessionState] = {}
        self._transaction_snapshots: dict[str, dict] = {}
        self._behavior = BehaviorStateStore(self.max_sessions)
        self._telemetry = StrategyTelemetryStore(self.max_sessions * 20)
        self._rewards = DeceptionRewardModel()
        self._shadow_bandit = shadow_bandit or ShadowLinUCB()
        self._learned_selector = BoundedLearnedSelector(
            learned_confidence_threshold, learned_minimum_updates
        )
        self._experiment = experiment_controller
        self._lock = threading.RLock()
        self.ready = False

    def _get_or_create(self, raw: dict, source_label: str = "") -> AuthoritativeSessionState | None:
        session_id = str(raw.get("session_id") or "").strip()[:_MAX_METADATA_CHARS]
        if not session_id:
            return None
        state = self._states.get(session_id)
        if state is None:
            if len(self._states) >= self.max_sessions:
                oldest = min(self._states, key=lambda key: self._states[key].updated_at or "")
                self._states.pop(oldest, None)
                self._transaction_snapshots.pop(oldest, None)
                self._behavior.remove(oldest)
            protocol = str(raw.get("protocol") or source_label).lower()
            if "mysql" in protocol:
                protocol = "mysql"
            elif protocol in {"pg", "postgresql"} or "postgres" in protocol:
                protocol = "postgres"
            state = AuthoritativeSessionState(session_id=session_id, protocol=protocol)
            self._states[session_id] = state
        self._ensure_experiment_assignment(state, raw, source_label)
        return state

    def _ensure_experiment_assignment(
        self, state: AuthoritativeSessionState, raw: dict, source_label: str
    ) -> None:
        if self._experiment is None or state.experiment_arm:
            return
        protocol = normalize_protocol(raw.get("protocol") or state.protocol or source_label)
        cohort_key = _bounded_experiment_identity(
            raw.get("client_ip") or raw.get("source_ip")
        )
        # MITRE or legacy events without a source identity must not lock a
        # session to a session-ID cohort before its proxy event arrives.
        if protocol == "unknown" or not cohort_key:
            return
        assignment = self._experiment.assign(state.session_id, protocol, cohort_key)
        state.experiment_id = str(assignment.get("experiment_id") or "")
        state.experiment_arm = str(assignment.get("assigned_arm") or "")
        state.experiment_mode = str(assignment.get("effective_mode") or "")
        state.experiment_assignment_version = str(
            assignment.get("assignment_version") or ""
        )
        state.experiment_cohort_hmac = str(assignment.get("cohort_hmac") or "")
        state.world_revision = int(assignment.get("world_revision") or 0)
        state.experiment_persisted = assignment.get("persisted") is True

    @staticmethod
    def _refresh_metadata(state: AuthoritativeSessionState, raw: dict) -> None:
        if raw.get("deceptive_principal_id"):
            for name in ("deceptive_principal_id", "principal_origin", "creator_session_id"):
                setattr(state, name, str(raw.get(name) or getattr(state, name))[:128])
            state.is_return_session = raw.get("is_return_session") is True
        state.protocol = str(raw.get("protocol") or state.protocol)[:32].lower().replace("postgresql", "postgres")
        state.database = str(raw.get("database") or state.database)[:_MAX_METADATA_CHARS]
        state.user = str(raw.get("username") or raw.get("db_user") or state.user)[:_MAX_METADATA_CHARS]
        if not state.role:
            state.role = state.user
        if state.database:
            state.visible_databases.add(state.database)
        timestamp = str(raw.get("timestamp") or "")
        if timestamp and (not state.started_at or timestamp < state.started_at):
            state.started_at = timestamp
        observed_at = timestamp or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        state.updated_at = max(state.updated_at, observed_at)

    def apply_proxy_event(self, raw: dict, source_label: str = "") -> None:
        if not isinstance(raw, dict):
            return
        with self._lock:
            state = self._get_or_create(raw, source_label)
            if state is None:
                return
            self._refresh_metadata(state, raw)
            self._behavior.apply_proxy_event(raw, source_label)
            event_type = str(raw.get("event_type") or "").lower()
            if event_type == "session_end":
                state.closed = True
                state.closed_at = str(raw.get("timestamp") or state.closed_at)
                try:
                    state.expected_query_count = max(
                        state.expected_query_count,
                        int(raw.get("query_count") or 0),
                    )
                except (TypeError, ValueError):
                    pass
                self._finalize_closed_if_complete(state)
                return
            if event_type != "query":
                return
            self._apply_query(state, raw)
            self._trim_state_sets(state)
            self._finalize_closed_if_complete(state)

    def _apply_query(self, state: AuthoritativeSessionState, raw: dict) -> None:
        state.query_count += 1
        state.session_depth = state.query_count
        state.last_query_fingerprint = str(raw.get("fingerprint") or "")[:128]
        verified = raw.get("outcome_verified") is True
        if not verified:
            state.unverified_query_count += 1
            return

        state.outcome_verified_count += 1
        success = raw.get("success") is True
        authority = str(raw.get("authority") or "").lower()
        if authority not in {"backend", "deception", "policy"}:
            authority = "unknown"
        state.database_authority = authority
        state.transaction_state = _transaction_state(str(raw.get("transaction_state") or ""))
        state.last_error_code = str(raw.get("error_code") or "")[:64]
        sql = str(raw.get("query_normalized") or "")[:_MAX_SQL_CHARS].lower().strip()

        if not success:
            state.failed_query_count += 1
            return

        if re.match(r"^(begin|start\s+transaction)\b", sql):
            self._transaction_snapshots[state.session_id] = self._state_snapshot(state)
            return
        if re.match(r"^rollback\b", sql):
            snapshot = self._transaction_snapshots.pop(state.session_id, None)
            if snapshot:
                self._restore_snapshot(state, snapshot)
                state.schema_version += 1
            state.transaction_state = "idle"
            return
        if re.match(r"^commit\b", sql):
            self._transaction_snapshots.pop(state.session_id, None)
            state.transaction_state = "idle"
            return

        relations = _extract_relations(sql)
        state.discovered_objects.update(relations)
        if authority == "deception":
            state.triggered_traps.update(relations & _TRAP_TABLES)
            return
        if authority != "backend":
            return

        changed = False
        created = _first_relation(sql, "create")
        if created:
            state.created_objects.add(created)
            state.dropped_objects.discard(created)
            state.visible_tables.add(created)
            state.visible_columns.update(_extract_create_columns(sql, created))
            changed = True

        dropped = _first_relation(sql, "drop")
        if dropped:
            state.dropped_objects.add(dropped)
            state.created_objects.discard(dropped)
            state.modified_objects.discard(dropped)
            state.visible_tables.discard(dropped)
            state.visible_columns = {column for column in state.visible_columns if not column.startswith(dropped + ".")}
            changed = True

        for operation in ("insert", "update", "delete", "alter"):
            relation = _first_relation(sql, operation)
            if relation:
                state.modified_objects.add(relation)
                state.visible_tables.add(relation)
                changed = True

        if success and not dropped:
            state.visible_tables.update(relations)

        role_match = re.match(r"^set\s+(?:local\s+)?role\s+([a-z_][a-z0-9_$]*)", sql, re.I)
        if role_match:
            state.role = role_match.group(1)
        elif re.match(r"^reset\s+role\b|^set\s+role\s+(?:none|default)\b", sql, re.I):
            state.role = state.user

        permission_match = re.match(
            r"^(grant|revoke)\s+([a-z_, ]+)\s+on\s+([^ ]+)\s+(?:to|from)\s+([a-z_][a-z0-9_$]*)",
            sql, re.I,
        )
        if permission_match:
            permission = ":".join(_clean_identifier(part) for part in permission_match.groups()[1:])
            if permission_match.group(1).lower() == "grant":
                state.permissions.add(permission)
            else:
                state.permissions.discard(permission)
            changed = True

        if changed:
            state.schema_version += 1

    @staticmethod
    def _trim_state_sets(state: AuthoritativeSessionState) -> None:
        for name in _STATE_SET_FIELDS:
            values = getattr(state, name)
            if len(values) > _MAX_OBJECTS_PER_SET:
                setattr(state, name, set(sorted(values)[:_MAX_OBJECTS_PER_SET]))

    def _finalize_closed_if_complete(self, state: AuthoritativeSessionState) -> None:
        if not state.closed or state.query_count < state.expected_query_count:
            return
        snapshot = self._transaction_snapshots.pop(state.session_id, None)
        if snapshot and state.transaction_state != "idle":
            self._restore_snapshot(state, snapshot)
            state.schema_version += 1
            state.transaction_state = "idle"

    @staticmethod
    def _state_snapshot(state: AuthoritativeSessionState) -> dict:
        names = (
            "permissions", "visible_databases", "visible_tables", "visible_columns",
            "created_objects", "modified_objects", "dropped_objects",
            "discovered_objects", "triggered_traps", "role",
        )
        return {name: copy.deepcopy(getattr(state, name)) for name in names}

    @staticmethod
    def _restore_snapshot(state: AuthoritativeSessionState, snapshot: dict) -> None:
        for name, value in snapshot.items():
            setattr(state, name, value)

    def apply_mitre_event(self, raw: dict) -> None:
        if not isinstance(raw, dict):
            return
        with self._lock:
            state = self._get_or_create(raw, "mitre")
            if state is None:
                return
            self._refresh_metadata(state, raw)
            self._behavior.apply_mitre_event(raw)
            stage = str(raw.get("phase") or raw.get("tactic") or "")[:_MAX_METADATA_CHARS]
            if stage:
                state.mitre_stage = stage
            try:
                observed_risk = float(raw.get("risk_score") or 0.0)
                if math.isfinite(observed_risk):
                    state.risk_score = max(state.risk_score, min(max(observed_risk, 0.0), 10_000.0))
            except (TypeError, ValueError):
                pass
            if raw.get("is_trap_triggered") is True:
                state.triggered_traps.add(str(raw.get("rule_id") or "mitre_trap")[:_MAX_METADATA_CHARS])
            self._trim_state_sets(state)

    def get(self, session_id: str) -> dict | None:
        with self._lock:
            state = self._states.get(session_id)
            if state is not None:
                self._refresh_experiment_state(state)
            return state.to_dict() if state else None

    def list(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(limit, 250))
        with self._lock:
            states = sorted(self._states.values(), key=lambda item: item.updated_at, reverse=True)
            for state in states[:limit]:
                self._refresh_experiment_state(state)
            return [state.to_dict() for state in states[:limit]]

    def _refresh_experiment_state(self, state: AuthoritativeSessionState) -> None:
        if self._experiment is None:
            return
        assignment = self._experiment.get_assignment(state.session_id)
        if assignment is None:
            return
        state.experiment_arm = str(assignment.get("assigned_arm") or state.experiment_arm)
        state.experiment_mode = str(assignment.get("effective_mode") or state.experiment_mode)
        state.world_revision = int(assignment.get("world_revision") or 0)
        state.experiment_persisted = assignment.get("persisted") is True

    def get_behavior(self, session_id: str) -> dict | None:
        """Return normalized behavior features without raw SQL or identities."""
        return self._behavior.get(session_id)

    def list_behavior(self, limit: int = 100) -> list[dict]:
        """Return bounded normalized behavior features for recent sessions."""
        return self._behavior.list(limit)


    def get_adaptation_snapshot(self, session_id: str) -> dict | None:
        """Return only structured fields required by the asynchronous selector."""
        with self._lock:
            state = self._states.get(session_id)
            if state is None:
                return None
            behavior = self._behavior.get(session_id) or {}
            persona = state.persona_id
            if persona == "deterministic-baseline":
                persona = "unknown"
            return {
                "session_state": {
                    "session_id": state.session_id,
                    "protocol": state.protocol,
                    "persona_id": persona,
                    "database": state.database,
                    "user": state.user,
                    "role": state.role,
                    "permissions": sorted(state.permissions),
                    "modified_objects": sorted(state.modified_objects),
                    "discovered_objects": sorted(state.discovered_objects),
                    "triggered_traps": sorted(state.triggered_traps),
                    "session_depth": state.session_depth,
                    "strategy_id": state.strategy_id,
                },
                "behavior_state": behavior,
                "mitre_state": {
                    "session_id": state.session_id,
                    "phase": state.mitre_stage,
                    "risk_score": state.risk_score,
                },
                "query_count": state.query_count,
                "failed_query_count": state.failed_query_count,
                "unverified_query_count": state.unverified_query_count,
                "state_inconsistency_count": self._consistency_violation_count(state),
                "observed_at": state.updated_at,
                "closed": state.closed,
                "closed_at": state.closed_at,
            }

    def record_strategy_decision(self, snapshot: dict, response: dict, **costs) -> dict | None:
        """Store telemetry only after set_next_strategy accepted the decision."""
        return self._telemetry.record_decision(snapshot, response, **costs)

    def evaluate_shadow(self, snapshot: dict, response: dict) -> dict:
        """Recommend in shadow only; any failure preserves the rule decision."""
        rule_default = response.get("rule_default_action") if isinstance(response, dict) else ""
        try:
            return self._shadow_bandit.recommend(
                snapshot,
                response.get("allowed_actions"),
                rule_default,
            )
        except Exception as exc:
            return self._shadow_bandit.unavailable(
                snapshot, rule_default, type(exc).__name__
            )

    def select_bounded_strategy(
        self,
        snapshot: dict,
        rule_decision: dict,
        model_evaluation: dict,
        operator_mode: str,
    ) -> dict:
        """Apply the local learned gate; every failure returns the rule default."""
        try:
            return self._learned_selector.select(
                rule_decision,
                model_evaluation,
                operator_mode,
                expected_session_id=str(
                    (snapshot.get("session_state") or {}).get("session_id") or ""
                ),
            )
        except Exception:
            if isinstance(rule_decision, dict):
                return self._learned_selector.select(
                    rule_decision, None, "RULE_ADAPTIVE"
                )
            raise

    def observe_strategy_outcomes(self, snapshot: dict) -> int:
        return self._telemetry.observe(snapshot)

    def get_strategy_telemetry(self, decision_id: str) -> dict | None:
        return self._telemetry.get(decision_id)

    def get_session_strategy_telemetry(self, session_id: str) -> dict:
        return self._telemetry.session(session_id)

    def list_strategy_telemetry(self, limit: int = 100) -> list[dict]:
        return self._telemetry.list(limit)

    @staticmethod
    def _consistency_violation_count(state: AuthoritativeSessionState) -> int:
        violations = len(state.created_objects & state.dropped_objects)
        violations += len(state.visible_tables & state.dropped_objects)
        if state.next_strategy_ready and (
            state.next_strategy_id not in _APPROVED_STRATEGY_IDS
            or (
                state.next_strategy_selector_type == "rule"
                and state.next_strategy_policy_version != "rule-v1"
            )
            or (
                state.next_strategy_selector_type == "learned"
                and state.next_strategy_policy_version != "bounded-learned-v1"
            )
            or state.next_strategy_selector_type not in {"rule", "learned"}
        ):
            violations += 1
        if (
            state.closed
            and state.query_count >= state.expected_query_count
            and state.transaction_state != "idle"
        ):
            violations += 1
        return violations

    def get_decision_reward(self, decision_id: str) -> dict | None:
        linked = self._telemetry.get(decision_id)
        return self._rewards.decision(linked) if linked else None

    def get_session_reward(self, session_id: str) -> dict | None:
        linked = self._telemetry.session(session_id)
        return self._rewards.session(linked) if linked["records"] else None

    def get_shadow_decision(self, decision_id: str) -> dict | None:
        linked = self._telemetry.get(decision_id)
        if not linked:
            return None
        shadow = linked["decision"].get("shadow_evaluation")
        if not isinstance(shadow, dict):
            return None
        return {
            "decision_id": decision_id,
            "session_id": linked["decision"]["session_id"],
            "rule_selected": linked["decision"]["selected_action"],
            "model_recommended": shadow.get("model_recommended", ""),
            "actual_execution": shadow.get("actual_execution", ""),
            "agreement": shadow.get("agreement", False),
            "shadow": copy.deepcopy(shadow),
            "observed_actual_reward": self._rewards.decision(linked),
        }

    def get_shadow_session(self, session_id: str) -> dict | None:
        linked = self._telemetry.session(session_id)
        if not linked["records"]:
            return None
        records = []
        for item in linked["records"]:
            decision_id = item["decision"]["decision_id"]
            evaluation = self.get_shadow_decision(decision_id)
            if evaluation:
                records.append(evaluation)
        if not records:
            return None
        available = [
            item for item in records if item["shadow"].get("status") == "AVAILABLE"
        ]
        agreements = sum(1 for item in available if item["agreement"] is True)
        rewards_complete = all(
            item["observed_actual_reward"]["status"] == "COMPLETE"
            for item in records
        )
        return {
            "session_id": session_id,
            "status": "COMPLETE" if rewards_complete else "PENDING",
            "shadow_only": True,
            "controls_execution": False,
            "decision_count": len(records),
            "recommendations_available": len(available),
            "agreements": agreements,
            "disagreements": len(available) - agreements,
            "agreement_rate": round(agreements / len(available), 6) if available else 0.0,
            "counterfactual_performance_claimed": False,
            "records": records,
        }

    def get_shadow_model_stats(self) -> dict:
        return self._shadow_bandit.stats()

    def get_learned_selection_policy(self) -> dict:
        return {
            **self._learned_selector.policy(),
            "model": self._shadow_bandit.stats(),
        }

    def experiment_status(self) -> dict | None:
        return self._experiment.status() if self._experiment is not None else None

    def experiment_assignment(self, session_id: str) -> dict | None:
        return (
            self._experiment.get_assignment(session_id)
            if self._experiment is not None else None
        )

    def experiment_assignments(self, limit: int = 100) -> list[dict]:
        return (
            self._experiment.list_assignments(limit)
            if self._experiment is not None else []
        )

    def experiment_ready(self) -> bool:
        return self._experiment is None or self._experiment.readiness_ok()

    def set_experiment_safe_mode(self, enabled, actor, reason) -> dict:
        if self._experiment is None:
            raise RuntimeError("experiment controller unavailable")
        return self._experiment.set_safe_mode(enabled, actor, reason)

    def set_experiment_forced_arm(self, arm, actor, reason) -> dict:
        if self._experiment is None:
            raise RuntimeError("experiment controller unavailable")
        return self._experiment.set_forced_arm(arm, actor, reason)

    def rollback_experiment_safe(self, actor, reason) -> dict:
        if self._experiment is None:
            raise RuntimeError("experiment controller unavailable")
        return self._experiment.rollback_safe(actor, reason)

    def set_next_strategy(
        self, session_id: str, decision: dict, expected_query_count: int
    ) -> bool:
        """Commit a fresh rule or bounded-learned decision for a future query."""
        if not validate_executable_decision(
            decision,
            expected_confidence_threshold=self._learned_selector.confidence_threshold
            if isinstance(decision, dict)
            and str(decision.get("selector_type") or "").lower() == "learned"
            else None,
            expected_minimum_updates=self._learned_selector.minimum_updates
            if isinstance(decision, dict)
            and str(decision.get("selector_type") or "").lower() == "learned"
            else None,
        ):
            return False
        strategy_id = str(decision.get("strategy_id") or "").strip().upper()
        selector_type = str(decision.get("selector_type") or "").strip().lower()
        policy_version = str(decision.get("policy_version") or "").strip()
        confidence = decision.get("confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            return False
        if not math.isfinite(confidence):
            return False
        with self._lock:
            state = self._states.get(session_id)
            if (
                state is None
                or state.closed
                or state.query_count != expected_query_count
            ):
                return False
            state.next_strategy_id = strategy_id
            state.next_strategy_ready = True
            state.next_strategy_confidence = confidence
            state.next_strategy_selector_type = selector_type
            state.next_strategy_policy_version = policy_version
            state.next_strategy_query_count = expected_query_count
            state.next_strategy_updated_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            )
            return True
class _StateAPIHandler(BaseHTTPRequestHandler):
    store: AuthoritativeStateStore

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send(200, {"status": "ok"})
            return
        if parsed.path == "/readyz":
            ready = self.store.ready and self.store.experiment_ready()
            payload = {"ready": ready}
            experiment = self.store.experiment_status()
            if experiment is not None:
                payload["experiment"] = experiment
            self._send(200 if ready else 503, payload)
            return
        if parsed.path == "/experiment/status":
            status = self.store.experiment_status()
            self._send(200, status) if status else self._send(503, {"error": "experiment controller unavailable"})
            return
        if parsed.path == "/experiment/assignments":
            try:
                limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
            except ValueError:
                self._send(400, {"error": "invalid limit"})
                return
            self._send(200, {"assignments": self.store.experiment_assignments(limit)})
            return
        if parsed.path == "/state/sessions":
            try:
                limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
            except ValueError:
                self._send(400, {"error": "invalid limit"})
                return
            self._send(200, {"sessions": self.store.list(limit)})
            return
        if parsed.path == "/behavior/sessions":
            try:
                limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
            except ValueError:
                self._send(400, {"error": "invalid limit"})
                return
            self._send(200, {"sessions": self.store.list_behavior(limit)})
            return
        if parsed.path == "/telemetry/decisions":
            try:
                limit = int(parse_qs(parsed.query).get("limit", ["100"])[0])
            except ValueError:
                self._send(400, {"error": "invalid limit"})
                return
            self._send(200, {"records": self.store.list_strategy_telemetry(limit)})
            return
        if parsed.path == "/shadow/model":
            self._send(200, self.store.get_shadow_model_stats())
            return
        if parsed.path == "/selection/policy":
            self._send(200, self.store.get_learned_selection_policy())
            return
        shadow_decision_prefix = "/shadow/decision/"
        if parsed.path.startswith(shadow_decision_prefix):
            decision_id = unquote(parsed.path[len(shadow_decision_prefix):])
            shadow = self.store.get_shadow_decision(decision_id)
            self._send(200, shadow) if shadow else self._send(404, {"error": "shadow decision not found"})
            return
        shadow_session_prefix = "/shadow/session/"
        if parsed.path.startswith(shadow_session_prefix):
            session_id = unquote(parsed.path[len(shadow_session_prefix):])
            shadow = self.store.get_shadow_session(session_id)
            self._send(200, shadow) if shadow else self._send(404, {"error": "shadow session not found"})
            return
        reward_decision_prefix = "/reward/decision/"
        if parsed.path.startswith(reward_decision_prefix):
            decision_id = unquote(parsed.path[len(reward_decision_prefix):])
            reward = self.store.get_decision_reward(decision_id)
            self._send(200, reward) if reward else self._send(404, {"error": "decision not found"})
            return
        reward_session_prefix = "/reward/session/"
        if parsed.path.startswith(reward_session_prefix):
            session_id = unquote(parsed.path[len(reward_session_prefix):])
            reward = self.store.get_session_reward(session_id)
            self._send(200, reward) if reward else self._send(404, {"error": "session not found"})
            return
        decision_prefix = "/telemetry/decision/"
        if parsed.path.startswith(decision_prefix):
            decision_id = unquote(parsed.path[len(decision_prefix):])
            record = self.store.get_strategy_telemetry(decision_id)
            self._send(200, record) if record else self._send(404, {"error": "decision not found"})
            return
        telemetry_session_prefix = "/telemetry/session/"
        if parsed.path.startswith(telemetry_session_prefix):
            session_id = unquote(parsed.path[len(telemetry_session_prefix):])
            record = self.store.get_session_strategy_telemetry(session_id)
            self._send(200, record) if record["records"] else self._send(404, {"error": "session not found"})
            return
        behavior_prefix = "/behavior/session/"
        if parsed.path.startswith(behavior_prefix):
            session_id = unquote(parsed.path[len(behavior_prefix):])
            state = self.store.get_behavior(session_id)
            self._send(200, state) if state else self._send(404, {"error": "session not found"})
            return
        prefix = "/state/session/"
        if parsed.path.startswith(prefix):
            session_id = unquote(parsed.path[len(prefix):])
            state = self.store.get(session_id)
            self._send(200, state) if state else self._send(404, {"error": "session not found"})
            return
        assignment_prefix = "/experiment/assignment/"
        if parsed.path.startswith(assignment_prefix):
            session_id = unquote(parsed.path[len(assignment_prefix):])
            assignment = self.store.experiment_assignment(session_id)
            self._send(200, assignment) if assignment else self._send(404, {"error": "assignment not found"})
            return
        self._send(404, {"error": "not found"})

    def _read_json(self, allowed: set[str]) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length <= 0 or length > 8192:
            raise ValueError("request body must be 1..8192 bytes")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid JSON body") from exc
        if not isinstance(payload, dict):
            raise ValueError("JSON body must be an object")
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError("unknown fields: " + ", ".join(sorted(unknown)))
        return payload

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/experiment/control/safe-mode":
                payload = self._read_json({"enabled", "actor", "reason"})
                result = self.store.set_experiment_safe_mode(
                    payload.get("enabled"), payload.get("actor"), payload.get("reason")
                )
            elif parsed.path == "/experiment/control/forced-arm":
                payload = self._read_json({"arm", "actor", "reason"})
                result = self.store.set_experiment_forced_arm(
                    payload.get("arm", ""), payload.get("actor"), payload.get("reason")
                )
            elif parsed.path == "/experiment/control/rollback":
                payload = self._read_json({"actor", "reason"})
                result = self.store.rollback_experiment_safe(
                    payload.get("actor"), payload.get("reason")
                )
            else:
                self._send(404, {"error": "not found"})
                return
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
            return
        except RuntimeError as exc:
            self._send(503, {"error": str(exc)})
            return
        self._send(200, result)

    def log_message(self, _format: str, *_args) -> None:
        return


def start_state_api(store: AuthoritativeStateStore, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("StateAPIHandler", (_StateAPIHandler,), {"store": store})
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, name="state-api", daemon=True).start()
    return server
