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
from reward_model import DeceptionRewardModel
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

    def to_dict(self) -> dict:
        payload = {}
        for name, value in self.__dict__.items():
            payload[name] = sorted(value) if isinstance(value, set) else value
        return payload


class AuthoritativeStateStore:
    """Thread-safe bounded state projection; persistence is intentionally Phase 24."""

    def __init__(self, max_sessions: int = 5000):
        self.max_sessions = min(max(1, max_sessions), 100_000)
        self._states: dict[str, AuthoritativeSessionState] = {}
        self._transaction_snapshots: dict[str, dict] = {}
        self._behavior = BehaviorStateStore(self.max_sessions)
        self._telemetry = StrategyTelemetryStore(self.max_sessions * 20)
        self._rewards = DeceptionRewardModel()
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
        return state

    @staticmethod
    def _refresh_metadata(state: AuthoritativeSessionState, raw: dict) -> None:
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
            return state.to_dict() if state else None

    def list(self, limit: int = 100) -> list[dict]:
        limit = max(1, min(limit, 250))
        with self._lock:
            states = sorted(self._states.values(), key=lambda item: item.updated_at, reverse=True)
            return [state.to_dict() for state in states[:limit]]

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
            or state.next_strategy_selector_type != "rule"
            or state.next_strategy_policy_version != "rule-v1"
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

    def set_next_strategy(
        self, session_id: str, decision: dict, expected_query_count: int
    ) -> bool:
        """Commit a fresh, validated rule-v1 decision without changing current strategy."""
        if not isinstance(decision, dict):
            return False
        strategy_id = str(decision.get("strategy_id") or "").strip().upper()
        selector_type = str(decision.get("selector_type") or "").strip().lower()
        policy_version = str(decision.get("policy_version") or "").strip()
        allowed_raw = decision.get("allowed_actions")
        rule_default = str(decision.get("rule_default_action") or "").strip().upper()
        confidence = decision.get("confidence")
        allowed = {
            str(item or "").strip().upper() for item in allowed_raw
        } if isinstance(allowed_raw, list) else set()
        if (
            strategy_id not in _APPROVED_STRATEGY_IDS
            or rule_default not in _APPROVED_STRATEGY_IDS
            or strategy_id != rule_default
            or strategy_id not in allowed
            or rule_default not in allowed
            or not allowed.issubset(_APPROVED_STRATEGY_IDS)
            or selector_type != "rule"
            or policy_version != "rule-v1"
            or isinstance(confidence, bool)
        ):
            return False
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            return False
        if not math.isfinite(confidence) or confidence != 1.0:
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
            self._send(200 if self.store.ready else 503, {"ready": self.store.ready})
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
        self._send(404, {"error": "not found"})

    def log_message(self, _format: str, *_args) -> None:
        return


def start_state_api(store: AuthoritativeStateStore, host: str, port: int) -> ThreadingHTTPServer:
    handler = type("StateAPIHandler", (_StateAPIHandler,), {"store": store})
    server = ThreadingHTTPServer((host, port), handler)
    threading.Thread(target=server.serve_forever, name="state-api", daemon=True).start()
    return server
