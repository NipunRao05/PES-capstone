"""Deterministic, bounded behavior features derived from internal structured events.

Raw SQL is inspected only long enough to classify it. It is never retained in
the accumulator and never returned by the behavior-state API.
"""

from __future__ import annotations

import math
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

FEATURE_VERSION = "behavior-v1"
RISK_NORMALIZATION_CEILING = 12.0
_MAX_QUERY_CHARS = 65536
_MAX_METADATA_CHARS = 256
_MAX_SESSIONS = 100_000
_MAX_SET_ITEMS = 512
_MAX_COUNTER = 1_000_000

_TRAP_TABLES = {
    "api_keys_backup", "salary_executives", "prod_credentials",
    "admin_tokens", "backup_passwords", "payment_tokens",
    "credit_cards_archive", "internal_api_keys", "aws_credentials",
}
_SENSITIVE_TABLES = {
    "employees", "payroll", "salary_executives", "accounts", "customers",
    "transactions", "payment_tokens", "credit_cards_archive", "contacts",
    "companies", "deals",
}
_CATALOG_TERMS = (
    "information_schema", "pg_catalog", "pg_tables", "pg_class",
    "pg_namespace", "pg_database", "show databases", "show schemas",
    "show tables", "show full tables", "show columns", "show fields",
)
_METADATA_TERMS = _CATALOG_TERMS + (
    "describe ", "desc ", "show create", "@@hostname", "@@version",
    "current_database", "current_schema",
)
_CREDENTIAL_TERMS = (
    "password", "passwd", "credential", "secret", "token", "api_key",
    "api key", "access_key", "mysql.user",
)
_BACKUP_TERMS = (
    "backup", "archive", "dump", "snapshot", "restore", "migration",
)
_ROLE_ENUM_TERMS = (
    "show grants", "mysql.user", "pg_roles", "pg_user", "current_user",
    "user_privileges", "schema_privileges", "table_privileges",
    "has_database_privilege", "has_schema_privilege", "has_table_privilege",
)
_STAGE_ORDER = {
    "": 0,
    "recon": 1,
    "enumeration": 2,
    "privilege_discovery": 3,
    "credential_access": 4,
    "data_discovery": 5,
    "exploitation": 6,
    "exfiltration": 7,
}
_RELATION = re.compile(
    r"\b(?:from|join|into|update|table|describe|desc)\s+"
    r"([A-Za-z_][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_][A-Za-z0-9_$]*)?)",
    re.I,
)
_SINGLE_QUOTED = re.compile(r"'(?:''|[^'])*'", re.S)
_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
_STRATEGY = re.compile(r"^D\d{1,4}$")


def _normalise_protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "mysql" in text:
        return "mysql"
    if text in {"pg", "postgres", "postgresql"} or text.startswith(("pg-", "postgres")):
        return "postgres"
    return ""


def _is_false(value: Any) -> bool:
    if value is False:
        return True
    if isinstance(value, str):
        return value.strip().lower() in {"false", "0", "no", "n"}
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == 0


def _bounded_counter(value: int) -> int:
    return min(max(int(value), 0), _MAX_COUNTER)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _timestamp_seconds(value: Any) -> float | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        number = _safe_float(value, float("nan"))
        return number if math.isfinite(number) and number >= 0 else None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _sanitise_sql(value: Any) -> str:
    text = str(value or "")[:_MAX_QUERY_CHARS].lower()
    text = _SINGLE_QUOTED.sub("?", text)
    text = _NUMBER.sub("?", text)
    return " ".join(text.split())


def _base_table(identifier: str) -> str:
    return identifier.replace(" ", "").strip('"').strip("`").split(".")[-1].strip('"').strip("`").lower()


def _relations(sql: str) -> set[str]:
    return {
        table for table in (_base_table(match) for match in _RELATION.findall(sql))
        if table and table not in {"select", "if", "exists"}
    }


def _contains_any(sql: str, terms: tuple[str, ...]) -> bool:
    return any(term in sql for term in terms)


def _select_stage(current: str, candidate: str) -> str:
    candidate = str(candidate or "").strip().lower()[:64]
    current = str(current or "").strip().lower()[:64]
    current_key = (_STAGE_ORDER.get(current, 0), current)
    candidate_key = (_STAGE_ORDER.get(candidate, 0), candidate)
    return candidate if candidate_key > current_key else current


@dataclass
class BehaviorAccumulator:
    session_id: str
    protocol: str = ""
    mitre_stage: str = ""
    risk_score_raw: float = 0.0
    query_count: int = 0
    failed_auth_count: int = 0
    catalog_query_count: int = 0
    metadata_query_count: int = 0
    credential_keyword_count: int = 0
    backup_keyword_count: int = 0
    sensitive_table_interest: int = 0
    role_enumeration_count: int = 0
    privilege_escalation_attempts: int = 0
    destructive_query_count: int = 0
    trap_trigger_count: int = 0
    observed_tables: set[str] = field(default_factory=set)
    query_families: set[str] = field(default_factory=set)
    mitre_techniques: set[str] = field(default_factory=set)
    current_strategy: str = "D0"
    strategy_history: list[str] = field(default_factory=lambda: ["D0"])
    first_event_ts: float | None = None
    last_event_ts: float | None = None
    closed: bool = False

    def _observe_common(self, raw: dict, source_label: str = "") -> None:
        protocol = _normalise_protocol(raw.get("protocol") or source_label)
        if protocol:
            self.protocol = protocol
        timestamp = _timestamp_seconds(raw.get("timestamp"))
        if timestamp is not None:
            self.first_event_ts = timestamp if self.first_event_ts is None else min(self.first_event_ts, timestamp)
            self.last_event_ts = timestamp if self.last_event_ts is None else max(self.last_event_ts, timestamp)
        strategy = str(raw.get("strategy_id") or "").strip().upper()
        if _STRATEGY.fullmatch(strategy) and strategy != self.current_strategy:
            self.current_strategy = strategy
            if not self.strategy_history or self.strategy_history[-1] != strategy:
                self.strategy_history.append(strategy)
                self.strategy_history = self.strategy_history[-64:]

    def apply_proxy_event(self, raw: dict, source_label: str = "") -> None:
        self._observe_common(raw, source_label)
        event_type = str(raw.get("event_type") or "").strip().lower()
        if event_type == "session_end":
            self.closed = True
            return
        if event_type == "auth_fail" or (
            event_type == "auth" and _is_false(raw.get("success"))
        ) or _is_false(raw.get("auth_success")):
            self.failed_auth_count = _bounded_counter(self.failed_auth_count + 1)
            self.query_families.add("authentication_failure")
            return
        if event_type != "query":
            return

        self.query_count = _bounded_counter(self.query_count + 1)
        sql = _sanitise_sql(raw.get("query_normalized"))
        tables = _relations(sql)
        self.observed_tables.update(tables)
        if len(self.observed_tables) > _MAX_SET_ITEMS:
            self.observed_tables = set(sorted(self.observed_tables)[:_MAX_SET_ITEMS])

        is_catalog = _contains_any(sql, _CATALOG_TERMS)
        is_credential = _contains_any(sql, _CREDENTIAL_TERMS)
        is_backup = _contains_any(sql, _BACKUP_TERMS)
        is_sensitive = bool(tables & _SENSITIVE_TABLES)
        is_role_enum = _contains_any(sql, _ROLE_ENUM_TERMS)
        is_metadata = _contains_any(sql, _METADATA_TERMS) or is_role_enum
        is_privilege = bool(re.match(
            r"^(?:grant|revoke|set\s+(?:local\s+)?role|"
            r"create\s+(?:user|role)|alter\s+(?:user|role)|"
            r"set\s+session\s+authorization)\b", sql
        ))
        is_destructive = bool(re.match(r"^(?:drop|truncate|delete|alter)\b", sql))
        is_trap_interest = bool(tables & _TRAP_TABLES)

        for attr, matched in (
            ("catalog_query_count", is_catalog),
            ("metadata_query_count", is_metadata),
            ("credential_keyword_count", is_credential),
            ("backup_keyword_count", is_backup),
            ("sensitive_table_interest", is_sensitive),
            ("role_enumeration_count", is_role_enum),
            ("privilege_escalation_attempts", is_privilege),
            ("destructive_query_count", is_destructive),
        ):
            if matched:
                setattr(self, attr, _bounded_counter(getattr(self, attr) + 1))

        verified_trap = (
            raw.get("outcome_verified") is True
            and raw.get("success") is True
            and str(raw.get("authority") or "").strip().lower() == "deception"
            and is_trap_interest
        )
        if verified_trap:
            self.trap_trigger_count = _bounded_counter(self.trap_trigger_count + 1)

        matched_families = {
            name for name, matched in (
                ("catalog", is_catalog), ("metadata", is_metadata),
                ("credential_interest", is_credential), ("backup_interest", is_backup),
                ("sensitive_data", is_sensitive), ("role_enumeration", is_role_enum),
                ("privilege_attempt", is_privilege), ("destructive", is_destructive),
                ("trap_interest", is_trap_interest),
            ) if matched
        }
        if sql.startswith(("select ", "with ", "show ", "describe ", "desc ")):
            matched_families.add("read")
        elif sql.startswith(("insert ", "update ", "delete ")):
            matched_families.add("write")
        elif sql.startswith(("begin", "start transaction", "commit", "rollback")):
            matched_families.add("transaction")
        elif not matched_families:
            matched_families.add("other")
        self.query_families.update(matched_families)
        if len(self.query_families) > _MAX_SET_ITEMS:
            self.query_families = set(sorted(self.query_families)[:_MAX_SET_ITEMS])

    def apply_mitre_event(self, raw: dict) -> None:
        self._observe_common(raw)
        self.mitre_stage = _select_stage(
            self.mitre_stage, raw.get("phase") or raw.get("tactic")
        )
        risk = _safe_float(raw.get("risk_score", raw.get("final_risk_score")), 0.0)
        self.risk_score_raw = max(self.risk_score_raw, min(max(risk, 0.0), 10_000.0))

        candidates: list[Any] = []
        if raw.get("technique_id"):
            candidates.append(raw.get("technique_id"))
        techniques = raw.get("techniques_matched")
        if isinstance(techniques, list):
            candidates.extend(techniques)
        for item in candidates:
            technique = item.get("technique_id") if isinstance(item, dict) else item
            technique = str(technique or "").strip()[:64]
            if technique:
                self.mitre_techniques.add(technique)
        if len(self.mitre_techniques) > _MAX_SET_ITEMS:
            self.mitre_techniques = set(sorted(self.mitre_techniques)[:_MAX_SET_ITEMS])

    def to_dict(self) -> dict[str, Any]:
        if self.first_event_ts is None or self.last_event_ts is None:
            duration = 0.0
        else:
            duration = max(0.0, self.last_event_ts - self.first_event_ts)
        qpm = (self.query_count / duration) * 60.0 if duration > 0 else 0.0
        risk_normalized = min(max(self.risk_score_raw / RISK_NORMALIZATION_CEILING, 0.0), 1.0)
        return {
            "feature_version": FEATURE_VERSION,
            "session_id": self.session_id,
            "protocol": self.protocol,
            "mitre_stage": self.mitre_stage,
            "risk_score": round(risk_normalized, 6),
            "risk_score_raw": round(self.risk_score_raw, 6),
            "catalog_query_count": self.catalog_query_count,
            "metadata_query_count": self.metadata_query_count,
            "credential_keyword_count": self.credential_keyword_count,
            "backup_keyword_count": self.backup_keyword_count,
            "sensitive_table_interest": self.sensitive_table_interest,
            "role_enumeration_count": self.role_enumeration_count,
            "privilege_escalation_attempts": self.privilege_escalation_attempts,
            "destructive_query_count": self.destructive_query_count,
            "trap_trigger_count": self.trap_trigger_count,
            "failed_auth_count": self.failed_auth_count,
            "unique_table_count": len(self.observed_tables),
            "unique_query_family_count": len(self.query_families),
            "mitre_technique_count": len(self.mitre_techniques),
            "session_duration_seconds": round(duration, 6),
            "queries_per_minute": round(qpm, 6),
            "query_count": self.query_count,
            "session_depth": self.query_count,
            "current_strategy": self.current_strategy,
            "previous_strategies": list(self.strategy_history[:-1]),
            "closed": self.closed,
        }


class BehaviorStateStore:
    """Thread-safe bounded store for normalized behavior feature state."""

    def __init__(self, max_sessions: int = 5000):
        self.max_sessions = min(max(1, int(max_sessions)), _MAX_SESSIONS)
        self._states: dict[str, BehaviorAccumulator] = {}
        self._lock = threading.RLock()

    def _get_or_create(self, raw: dict) -> BehaviorAccumulator | None:
        session_id = str(raw.get("session_id") or "").strip()[:_MAX_METADATA_CHARS]
        if not session_id:
            return None
        state = self._states.get(session_id)
        if state is None:
            if len(self._states) >= self.max_sessions:
                oldest = min(
                    self._states,
                    key=lambda key: (
                        self._states[key].last_event_ts
                        if self._states[key].last_event_ts is not None else -1.0,
                        key,
                    ),
                )
                self._states.pop(oldest, None)
            state = BehaviorAccumulator(session_id=session_id)
            self._states[session_id] = state
        return state

    def apply_proxy_event(self, raw: dict, source_label: str = "") -> None:
        if not isinstance(raw, dict):
            return
        with self._lock:
            state = self._get_or_create(raw)
            if state is not None:
                state.apply_proxy_event(raw, source_label)

    def apply_mitre_event(self, raw: dict) -> None:
        if not isinstance(raw, dict):
            return
        with self._lock:
            state = self._get_or_create(raw)
            if state is not None:
                state.apply_mitre_event(raw)

    def remove(self, session_id: str) -> None:
        with self._lock:
            self._states.pop(session_id, None)

    def get(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            state = self._states.get(session_id)
            return state.to_dict() if state else None

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 250))
        with self._lock:
            states = sorted(
                self._states.values(),
                key=lambda item: (
                    item.last_event_ts if item.last_event_ts is not None else -1.0,
                    item.session_id,
                ),
                reverse=True,
            )
            return [item.to_dict() for item in states[:limit]]
