from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import redis
import requests
from fastapi import FastAPI, HTTPException, Query
from kafka import KafkaConsumer
from pydantic import BaseModel, Field


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("evidence-store")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "redpanda:9092")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "evidence-store-v1")
KAFKA_OFFSET_RESET = os.getenv("KAFKA_OFFSET_RESET", "latest")
KAFKA_TOPICS = tuple(
    topic.strip()
    for topic in os.getenv(
        "KAFKA_TOPICS",
        "mysql-query-events,pg-query-events,mysql-session-events,pg-session-events,"
        "session-profiles,mitre-events,mitre-sessions",
    ).split(",")
    if topic.strip()
)
REDIS_HOST = os.getenv("REDIS_HOST", "redis-mitre")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
SCALING_AGENT_URL = os.getenv("SCALING_AGENT_URL", "http://scaling-agent:8080")
SESSION_MODULE_URL = os.getenv("SESSION_MODULE_URL", "http://session-module:8003")
POLL_TIMEOUT_SECONDS = float(os.getenv("POLL_TIMEOUT_SECONDS", "2"))
SCALE_POLL_INTERVAL_SECONDS = float(os.getenv("SCALE_POLL_INTERVAL_SECONDS", "2"))
ADAPTIVE_POLL_INTERVAL_SECONDS = float(os.getenv("ADAPTIVE_POLL_INTERVAL_SECONDS", "2"))
EVIDENCE_TTL_SECONDS = int(os.getenv("EVIDENCE_TTL_SECONDS", str(30 * 24 * 60 * 60)))
MAX_QUERY_EVENTS = int(os.getenv("MAX_QUERY_EVENTS", "500"))
MAX_STAGE_EVENTS = int(os.getenv("MAX_STAGE_EVENTS", "100"))
MAX_TEXT_LENGTH = int(os.getenv("MAX_TEXT_LENGTH", "16384"))
MAX_ARTIFACT_BYTES = int(os.getenv("MAX_ARTIFACT_BYTES", str(256 * 1024)))

SESSION_PREFIX = "evidence:session:"
SESSION_INDEX = "evidence:sessions"
IP_SALT_KEY = "evidence:config:ip_hash_salt"

_SQL_STRING = re.compile(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"", re.DOTALL)
_PASSWORD_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*([^\s,;)]+)"
)
_IDENTIFIED_BY = re.compile(r"(?i)(\bidentified\s+by\s+)([^\s;]+)")
_HEX_LITERAL = re.compile(r"(?i)\b0x[0-9a-f]{8,}\b")
_LONG_NUMBER = re.compile(r"\b\d{4,}\b")

ARTIFACT_COLLECTIONS = {
    "session_state": "session_states",
    "strategy_decision": "strategy_decisions",
    "strategy_reward": "strategy_rewards",
    "replay_result": "replay_results",
    "hardening_finding": "hardening_findings",
    "learning_analysis": "learning_analyses",
    "proposal": "proposals",
    "analyst_report": "analyst_reports",
}
_SENSITIVE_ARTIFACT_KEYS = {
    "client_ip", "source_ip", "password", "passwd", "pwd", "secret", "token",
    "api_key", "api-key", "credential", "credentials", "raw_payload",
}
_QUERY_ARTIFACT_KEYS = {"query", "query_raw", "query_normalized", "sql"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_timestamp(value: Any) -> str:
    """Normalize ISO or legacy epoch evidence time to UTC ISO-8601."""
    text = bounded_text(value, 128).strip()
    try:
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            parsed = datetime.fromtimestamp(float(text), tz=timezone.utc)
        else:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            parsed = parsed.astimezone(timezone.utc)
        return parsed.isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return utc_now()


def timestamp_score(value: Any) -> float:
    """Convert bounded event time to a safe Redis index score."""
    now = time.time()
    try:
        parsed = datetime.fromisoformat(canonical_timestamp(value).replace("Z", "+00:00"))
        score = parsed.timestamp()
    except (ValueError, OverflowError, OSError):
        return now
    if not math.isfinite(score) or score < 0:
        return now
    return min(score, now + 300.0)


def bounded_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:limit]


def decode_json_object(value: Any) -> dict[str, Any] | None:
    """Decode one Kafka value without allowing malformed input to stop ingestion."""
    try:
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode("utf-8")
        payload = json.loads(value) if isinstance(value, str) else value
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def redact_query(value: Any) -> str:
    """Preserve SQL structure while removing literals and credential-like values."""
    text = bounded_text(value)
    text = _SQL_STRING.sub("'[REDACTED]'", text)
    text = _PASSWORD_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _IDENTIFIED_BY.sub(r"\1[REDACTED]", text)
    text = _HEX_LITERAL.sub("[REDACTED_HEX]", text)
    return _LONG_NUMBER.sub("[REDACTED_NUMBER]", text)


def stable_id(*parts: Any) -> str:
    payload = "\x1f".join(bounded_text(part, 4096) for part in parts)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def kafka_event_id(payload: dict[str, Any], topic: str, partition: int, offset: int, session_id: str) -> str:
    upstream = bounded_text(payload.get("event_id"), 256).strip()
    return upstream or stable_id("kafka", topic, partition, offset, session_id)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_nonnegative_int(value: Any, default: int = 0) -> int:
    number = safe_float(value, float(default))
    if not math.isfinite(number) or number < 0:
        return default
    return int(number)


def safe_json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def sanitize_artifact(value: Any, *, key: str = "", depth: int = 0) -> Any:
    """Bound internal structured evidence and remove secret/source material."""
    if depth > 8:
        raise ValueError("artifact nesting exceeds the evidence boundary")
    normalized_key = key.strip().lower()
    safe_derived_feature = (
        isinstance(value, (bool, int, float))
        and normalized_key.endswith((
            "_count", "_score", "_ratio", "_rate", "_present", "_detected",
            "_attempts", "_interest", "_confidence",
        ))
    )
    sensitive_key = (
        normalized_key in _SENSITIVE_ARTIFACT_KEYS
        or any(
            marker in normalized_key
            for marker in (
                "password", "passwd", "credential", "secret", "token",
                "api_key", "apikey", "source_ip", "client_ip", "source_address",
            )
        )
    )
    if sensitive_key and not safe_derived_feature:
        return "[REDACTED]"
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("artifact contains a non-finite number")
        return value
    if isinstance(value, str):
        if normalized_key in {
            "timestamp", "created_at", "updated_at", "observed_at",
            "first_seen", "last_seen", "closed_at", "started_at",
        }:
            return canonical_timestamp(value)
        return redact_query(value) if normalized_key in _QUERY_ARTIFACT_KEYS else bounded_text(value)
    if isinstance(value, list):
        if len(value) > 500:
            raise ValueError("artifact list exceeds the evidence boundary")
        return [sanitize_artifact(item, key=key, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > 256:
            raise ValueError("artifact object exceeds the evidence boundary")
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            item_key = bounded_text(raw_key, 128).strip()
            if not item_key:
                raise ValueError("artifact keys must be nonempty")
            result[item_key] = sanitize_artifact(item, key=item_key, depth=depth + 1)
        return result
    raise ValueError("artifact contains an unsupported value type")


def validate_artifact_link(
    session_id: Any,
    artifact_type: Any,
    artifact_id: Any,
    payload: Any,
) -> tuple[str, str, str, dict[str, Any]]:
    session = bounded_text(session_id, 512).strip()
    kind = bounded_text(artifact_type, 64).strip().lower()
    identity = bounded_text(artifact_id, 128).strip()
    if not session or not identity or kind not in ARTIFACT_COLLECTIONS:
        raise ValueError("valid session_id, artifact_type, and artifact_id are required")
    if not isinstance(payload, dict):
        raise ValueError("artifact payload must be an object")
    sanitized = sanitize_artifact(payload)
    encoded = json.dumps(
        sanitized, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact payload exceeds the evidence boundary")
    linked_sessions: set[str] = set()

    def collect_session_ids(item: Any) -> None:
        if isinstance(item, dict):
            for item_key, child in item.items():
                if item_key.strip().lower() == "session_id":
                    linked = bounded_text(child, 512).strip()
                    if linked:
                        linked_sessions.add(linked)
                else:
                    collect_session_ids(child)
        elif isinstance(item, list):
            for child in item:
                collect_session_ids(child)

    collect_session_ids(sanitized)
    if any(linked != session for linked in linked_sessions):
        raise ValueError("cross-session artifact linkage is forbidden")
    return session, kind, identity, sanitized


class EvidenceRepository:
    def __init__(self, client: redis.Redis):
        self.client = client
        self._touch_lock = threading.Lock()
        configured_salt = os.getenv("EVIDENCE_IP_HASH_SALT", "").encode("utf-8")
        if configured_salt:
            self.ip_hash_salt = configured_salt
        else:
            self.client.setnx(IP_SALT_KEY, secrets.token_hex(32))
            stored_salt = self.client.get(IP_SALT_KEY)
            if not stored_salt:
                raise RuntimeError("could not initialise evidence IP hashing salt")
            self.ip_hash_salt = stored_salt.encode("utf-8")

    @staticmethod
    def _record_key(session_id: str) -> str:
        return f"{SESSION_PREFIX}{session_id}"

    @classmethod
    def _child_key(cls, session_id: str, suffix: str) -> str:
        return f"{cls._record_key(session_id)}:{suffix}"

    def hash_source_ip(self, source_ip: Any) -> str:
        value = bounded_text(source_ip, 256).strip()
        if not value:
            return ""
        digest = hmac.new(self.ip_hash_salt, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest[:24]}"

    def _expire_session_keys(self, session_id: str) -> None:
        keys = [
            self._record_key(session_id),
            self._child_key(session_id, "queries"),
            self._child_key(session_id, "session_events"),
            self._child_key(session_id, "mitre_events"),
            self._child_key(session_id, "trap_events"),
            self._child_key(session_id, "scaling_events"),
            self._child_key(session_id, "ai_reports"),
            self._child_key(session_id, "event_ids"),
        ]
        keys.extend(
            self._child_key(session_id, collection)
            for collection in ARTIFACT_COLLECTIONS.values()
        )
        pipe = self.client.pipeline(transaction=False)
        for key in keys:
            pipe.expire(key, EVIDENCE_TTL_SECONDS)
        pipe.execute()

    def _touch(self, session_id: str, payload: dict[str, Any], timestamp: str) -> None:
        with self._touch_lock:
            self._touch_locked(session_id, payload, timestamp)

    def _touch_locked(self, session_id: str, payload: dict[str, Any], timestamp: str) -> None:
        key = self._record_key(session_id)
        event_score = timestamp_score(timestamp)
        current_first_seen = self.client.hget(key, "first_seen")
        current_last_seen = self.client.hget(key, "last_seen")
        source_ip = payload.get("client_ip") or payload.get("source_ip")
        protocol = bounded_text(payload.get("protocol"), 32).lower()
        mapping = {
            "schema_version": "2",
            "session_id": session_id,
            "trace_id": "TR-" + stable_id("evidence-trace-v2", session_id)[:24],
        }
        if not current_first_seen or event_score < timestamp_score(current_first_seen):
            mapping["first_seen"] = timestamp
        if not current_last_seen or event_score >= timestamp_score(current_last_seen):
            mapping["last_seen"] = timestamp
        optional = {
            "source_ip_hash": self.hash_source_ip(source_ip),
            "fingerprint": bounded_text(payload.get("fingerprint"), 512),
            "protocol": protocol,
            "database_attempted": bounded_text(payload.get("database"), 256),
            "user_attempted": bounded_text(payload.get("username") or payload.get("db_user"), 256),
        }
        mapping.update({name: value for name, value in optional.items() if value})

        pipe = self.client.pipeline(transaction=False)
        pipe.hset(key, mapping=mapping)
        prior_score = self.client.zscore(SESSION_INDEX, session_id)
        score = max(float(prior_score or 0.0), event_score)
        pipe.zadd(SESSION_INDEX, {session_id: score})
        pipe.expire(key, EVIDENCE_TTL_SECONDS)
        pipe.execute()

    def _append_once(
        self,
        session_id: str,
        collection: str,
        event_id: str,
        payload: dict[str, Any],
        maximum: int,
    ) -> bool:
        id_key = self._child_key(session_id, "event_ids")
        if self.client.sadd(id_key, event_id) != 1:
            return False
        list_key = self._child_key(session_id, collection)
        pipe = self.client.pipeline(transaction=False)
        pipe.rpush(list_key, json.dumps(payload, separators=(",", ":"), default=str))
        pipe.ltrim(list_key, -maximum, -1)
        pipe.expire(list_key, EVIDENCE_TTL_SECONDS)
        pipe.expire(id_key, EVIDENCE_TTL_SECONDS)
        pipe.execute()
        return True

    def _merge_technique(self, session_id: str, technique_id: str) -> None:
        if not technique_id:
            return
        key = self._record_key(session_id)
        techniques = safe_json(self.client.hget(key, "mitre_techniques"), [])
        if technique_id not in techniques:
            techniques.append(technique_id)
            self.client.hset(key, "mitre_techniques", json.dumps(techniques))

    def ingest_kafka(
        self,
        topic: str,
        payload: dict[str, Any],
        partition: int,
        offset: int,
    ) -> bool:
        session_id = bounded_text(payload.get("session_id"), 512).strip()
        if not session_id:
            log.warning("Ignoring evidence event without session_id: topic=%s offset=%s", topic, offset)
            return False

        timestamp = canonical_timestamp(
            payload.get("timestamp") or payload.get("timestamp_closed") or payload.get("created_at"),
        )
        event_id = kafka_event_id(payload, topic, partition, offset, session_id)
        self._touch(session_id, payload, timestamp)

        if topic in {"mysql-query-events", "pg-query-events"}:
            response = {
                "outcome_verified": payload.get("outcome_verified") is True,
                "success": payload.get("success") is True,
                "authority": bounded_text(payload.get("authority"), 32).lower(),
                "transaction_state": bounded_text(payload.get("transaction_state"), 64),
                "error_code": bounded_text(payload.get("error_code"), 64),
                "bytes_out": safe_nonnegative_int(payload.get("bytes_out")),
            }
            query = {
                "event_id": event_id,
                "timestamp": timestamp,
                "protocol": bounded_text(payload.get("protocol"), 32).lower(),
                "database": bounded_text(payload.get("database"), 256),
                "fingerprint": bounded_text(payload.get("fingerprint"), 512),
                "query_raw": redact_query(payload.get("query_raw")),
                "query_normalized": redact_query(payload.get("query_normalized")),
                "response": response,
                "strategy_id": bounded_text(payload.get("strategy_id"), 32).upper(),
                "source_topic": topic,
                "source_partition": partition,
                "source_offset": offset,
            }
            appended = self._append_once(session_id, "queries", event_id, query, MAX_QUERY_EVENTS)
            if appended:
                self.client.hset(
                    self._record_key(session_id),
                    mapping={
                        "latest_query_raw": query["query_raw"],
                        "latest_query_normalized": query["query_normalized"],
                    },
                )

        elif topic in {"mysql-session-events", "pg-session-events", "session-profiles"}:
            event = {
                "event_id": event_id,
                "event_type": bounded_text(payload.get("event_type") or "session_profile", 64),
                "timestamp": timestamp,
                "protocol": bounded_text(payload.get("protocol"), 32).lower(),
                "database": bounded_text(payload.get("database"), 256),
                "user_attempted": bounded_text(payload.get("username") or payload.get("db_user"), 256),
                "auth_success": payload.get("success") if "success" in payload else None,
                "close_reason": bounded_text(payload.get("close_reason"), 256),
                "query_count": payload.get("query_count"),
                "source_topic": topic,
                "source_partition": partition,
                "source_offset": offset,
                "provenance": "summary" if topic == "mitre-sessions" else "detailed",
            }
            self._append_once(session_id, "session_events", event_id, event, MAX_STAGE_EVENTS)

        elif topic in {"mitre-events", "mitre-sessions"}:
            technique_id = bounded_text(payload.get("technique_id"), 64)
            event = {
                "event_id": event_id,
                "timestamp": timestamp,
                "technique_id": technique_id,
                "technique_name": bounded_text(payload.get("technique_name"), 256),
                "rule_id": bounded_text(payload.get("rule_id"), 128),
                "risk_score": safe_float(payload.get("risk_score", payload.get("final_risk_score"))),
                "risk_level": bounded_text(payload.get("risk_level"), 32).lower(),
                "trap_triggered": bool(payload.get("is_trap_triggered", payload.get("trap_triggered", False))),
                "logical_trap_interaction": (
                    topic == "mitre-events"
                    and bool(payload.get("is_trap_triggered", payload.get("trap_triggered", False)))
                ),
                "source_topic": topic,
                "source_partition": partition,
                "source_offset": offset,
            }
            if topic == "mitre-sessions":
                event["techniques_matched"] = payload.get("techniques_matched", [])
            if self._append_once(session_id, "mitre_events", event_id, event, MAX_STAGE_EVENTS):
                key = self._record_key(session_id)
                mapping = {
                    "risk_score": str(event["risk_score"]),
                    "risk_level": event["risk_level"],
                }
                if event["trap_triggered"]:
                    mapping["trap_triggered"] = "1"
                self.client.hset(key, mapping=mapping)
                self._merge_technique(session_id, technique_id)
                for match in payload.get("techniques_matched", []):
                    if isinstance(match, dict):
                        self._merge_technique(session_id, bounded_text(match.get("technique_id"), 64))
                if event["trap_triggered"] and topic == "mitre-events":
                    self._append_once(
                        session_id,
                        "trap_events",
                        f"trap:{event_id}",
                        {
                            "trap_event_id": f"trap:{event_id}",
                            "timestamp": timestamp,
                            "technique_id": technique_id,
                            "risk_score": event["risk_score"],
                            "source_event_id": event_id,
                            "logical_interaction": True,
                            "provenance": "detailed",
                        },
                        MAX_STAGE_EVENTS,
                    )

        self._expire_session_keys(session_id)
        return True

    def ingest_scale_event(self, payload: dict[str, Any]) -> bool:
        session_id = bounded_text(payload.get("session_id"), 512).strip()
        if not session_id or session_id.startswith("metric-pressure-"):
            return False
        timestamp = canonical_timestamp(payload.get("timestamp"))
        scale_event_id = stable_id(
            "scale",
            session_id,
            timestamp,
            payload.get("replica_target"),
            payload.get("raw_score"),
        )
        event = {
            "scale_event_id": scale_event_id,
            "session_id": session_id,
            "timestamp": timestamp,
            "raw_score": safe_float(payload.get("raw_score")),
            "smoothed_score": safe_float(payload.get("smoothed_score")),
            "replica_target": int(safe_float(payload.get("replica_target"), 1)),
            "reason": bounded_text(payload.get("reason"), 2048),
        }
        self._touch(session_id, payload, timestamp)
        if not self._append_once(session_id, "scaling_events", scale_event_id, event, MAX_STAGE_EVENTS):
            return False
        self.client.hset(self._record_key(session_id), "scale_event_id", scale_event_id)
        self._expire_session_keys(session_id)
        return True

    def ingest_ai_report(self, payload: dict[str, Any]) -> bool:
        session_id = bounded_text(payload.get("session_id"), 512).strip()
        report_id = bounded_text(payload.get("report_id"), 128).strip()
        if not session_id or not report_id:
            return False
        generated_at = canonical_timestamp(payload.get("generated_at"))
        event = {
            "ai_report_id": report_id,
            "session_id": session_id,
            "generated_at": generated_at,
            "risk_level": bounded_text(payload.get("risk_level"), 32).lower(),
            "summary": bounded_text(payload.get("summary"), 4096),
        }
        self._touch(session_id, {}, generated_at)
        event_id = stable_id("ai-report", report_id)
        if not self._append_once(session_id, "ai_reports", event_id, event, MAX_STAGE_EVENTS):
            return False
        self.client.hset(self._record_key(session_id), "ai_report_id", report_id)
        self._expire_session_keys(session_id)
        return True

    def ingest_artifact(
        self,
        session_id: Any,
        artifact_type: Any,
        artifact_id: Any,
        payload: Any,
        timestamp: Any = "",
    ) -> bool:
        session, kind, identity, sanitized = validate_artifact_link(
            session_id, artifact_type, artifact_id, payload
        )
        observed_at = canonical_timestamp(timestamp)
        record = {
            "artifact_type": kind,
            "artifact_id": identity,
            "session_id": session,
            "timestamp": observed_at,
            "payload": sanitized,
        }
        collection = ARTIFACT_COLLECTIONS[kind]
        event_id = "artifact:" + stable_id(
            kind,
            identity,
            json.dumps(sanitized, sort_keys=True, separators=(",", ":"), allow_nan=False),
        )
        self._touch(session, {}, observed_at)
        appended = self._append_once(
            session, collection, event_id, record, MAX_STAGE_EVENTS
        )
        if appended:
            self.client.hset(
                self._record_key(session), f"latest_{kind}_id", identity
            )
        self._expire_session_keys(session)
        return appended

    def _load_list(self, session_id: str, suffix: str) -> list[dict[str, Any]]:
        values = self.client.lrange(self._child_key(session_id, suffix), 0, -1)
        records = [item for item in (safe_json(value, None) for value in values) if isinstance(item, dict)]
        return sorted(
            records,
            key=lambda item: (
                timestamp_score(item.get("timestamp") or item.get("created_at")),
                bounded_text(item.get("event_id") or item.get("artifact_id"), 256),
            ),
        )

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        record = self.client.hgetall(self._record_key(session_id))
        if not record:
            return None
        queries = self._load_list(session_id, "queries")
        session_events = self._load_list(session_id, "session_events")
        mitre_events = self._load_list(session_id, "mitre_events")
        trap_events = self._load_list(session_id, "trap_events")
        scaling_events = self._load_list(session_id, "scaling_events")
        ai_reports = self._load_list(session_id, "ai_reports")
        artifacts = {
            kind: self._load_list(session_id, collection)
            for kind, collection in ARTIFACT_COLLECTIONS.items()
        }
        latest_query = queries[-1] if queries else {}
        techniques = safe_json(record.get("mitre_techniques"), [])
        result = {
            "schema_version": int(record.get("schema_version", "1")),
            "session_id": record.get("session_id", session_id),
            "trace_id": record.get("trace_id", ""),
            "source_ip_hash": record.get("source_ip_hash", ""),
            "fingerprint": record.get("fingerprint", latest_query.get("fingerprint", "")),
            "protocol": record.get("protocol", ""),
            "database_attempted": record.get("database_attempted", ""),
            "user_attempted": record.get("user_attempted", ""),
            "query_raw": record.get("latest_query_raw", ""),
            "query_normalized": record.get("latest_query_normalized", ""),
            "timestamp": record.get("last_seen", ""),
            "first_seen": record.get("first_seen", ""),
            "last_seen": record.get("last_seen", ""),
            "trap_triggered": record.get("trap_triggered", "0") == "1",
            "mitre_technique": techniques,
            "risk_score": safe_float(record.get("risk_score")),
            "risk_level": record.get("risk_level", "low"),
            "scale_event_id": record.get("scale_event_id"),
            "ai_report_id": record.get("ai_report_id"),
            "queries": queries,
            "responses": [item.get("response", {}) for item in queries],
            "connection_events": session_events,
            "mitre_events": mitre_events,
            "trap_events": trap_events,
            "scaling_events": scaling_events,
            "ai_reports": ai_reports,
            "session_states": artifacts["session_state"],
            "strategy_decisions": artifacts["strategy_decision"],
            "strategy_rewards": artifacts["strategy_reward"],
            "replay_results": artifacts["replay_result"],
            "hardening_findings": artifacts["hardening_finding"],
            "learning_analyses": artifacts["learning_analysis"],
            "proposals": artifacts["proposal"],
            "proposal_ids": [item["artifact_id"] for item in artifacts["proposal"]],
            "analyst_reports": artifacts["analyst_report"],
            "analyst_report_ids": [
                item["artifact_id"] for item in artifacts["analyst_report"]
            ],
        }
        stages = {
            "connection": bool(session_events),
            "query": bool(queries),
            "response": bool(queries) and all(bool(item.get("response")) for item in queries),
            "session_state": bool(artifacts["session_state"]),
            "mitre": bool(mitre_events),
            "trap": bool(trap_events),
            "strategy_decision": bool(artifacts["strategy_decision"]),
            "strategy_reward": bool(artifacts["strategy_reward"]),
            "scaling": bool(scaling_events),
            "ai_report": bool(ai_reports),
            "replay": bool(artifacts["replay_result"]),
            "hardening": bool(artifacts["hardening_finding"]),
            "learning_analysis": bool(artifacts["learning_analysis"]),
            "proposal": bool(artifacts["proposal"]),
            "analyst_report": bool(artifacts["analyst_report"]),
        }
        core = (
            "connection", "query", "response", "session_state", "mitre",
            "strategy_decision", "strategy_reward", "scaling", "ai_report",
            "replay", "hardening",
        )
        result["trace"] = {
            **stages,
            "core_complete": all(stages[name] for name in core),
            "complete": all(stages.values()),
            "missing": [name for name, available in stages.items() if not available],
        }
        return result

    def list_sessions(self, limit: int) -> list[dict[str, Any]]:
        session_ids = self.client.zrevrange(SESSION_INDEX, 0, max(0, limit - 1))
        results = []
        for session_id in session_ids:
            record = self.get_session(session_id)
            if record:
                results.append(record)
        return results


class EvidenceConsumer(threading.Thread):
    def __init__(self, repository: EvidenceRepository, stop_event: threading.Event):
        super().__init__(name="evidence-kafka-consumer", daemon=True)
        self.repository = repository
        self.stop_event = stop_event
        self.connected = False
        self.last_error = ""
        self.consumer: KafkaConsumer | None = None

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.consumer = KafkaConsumer(
                    *KAFKA_TOPICS,
                    bootstrap_servers=KAFKA_BROKERS,
                    group_id=KAFKA_GROUP_ID,
                    auto_offset_reset=KAFKA_OFFSET_RESET,
                    enable_auto_commit=True,
                    consumer_timeout_ms=1000,
                )
                self.connected = True
                self.last_error = ""
                log.info("Evidence consumer subscribed to %s", ",".join(KAFKA_TOPICS))
                while not self.stop_event.is_set():
                    for message in self.consumer:
                        if self.stop_event.is_set():
                            break
                        payload = decode_json_object(message.value)
                        if payload is None:
                            log.warning(
                                "Ignoring malformed or non-object evidence event: topic=%s partition=%s offset=%s",
                                message.topic,
                                message.partition,
                                message.offset,
                            )
                            continue
                        try:
                            self.repository.ingest_kafka(
                                message.topic,
                                payload,
                                message.partition,
                                message.offset,
                            )
                        except Exception:
                            log.exception(
                                "Evidence ingestion failed: topic=%s partition=%s offset=%s",
                                message.topic,
                                message.partition,
                                message.offset,
                            )
            except Exception as exc:
                self.connected = False
                self.last_error = str(exc)
                log.error("Evidence consumer error: %s", exc)
                self.stop_event.wait(2)
            finally:
                consumer, self.consumer = self.consumer, None
                if consumer:
                    try:
                        consumer.close()
                    except Exception:
                        log.exception("Failed to close evidence Kafka consumer")

    def close(self) -> None:
        if self.consumer:
            try:
                self.consumer.close()
            except Exception:
                log.exception("Failed to close evidence Kafka consumer")


class ScalingEventPoller(threading.Thread):
    def __init__(self, repository: EvidenceRepository, stop_event: threading.Event):
        super().__init__(name="evidence-scaling-poller", daemon=True)
        self.repository = repository
        self.stop_event = stop_event
        self.available = False
        self.last_error = ""

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                response = requests.get(
                    f"{SCALING_AGENT_URL}/scale/events",
                    timeout=POLL_TIMEOUT_SECONDS,
                )
                response.raise_for_status()
                payload = response.json()
                for event in payload.get("events", []):
                    if isinstance(event, dict):
                        self.repository.ingest_scale_event(event)
                self.available = True
                self.last_error = ""
            except Exception as exc:
                self.available = False
                self.last_error = str(exc)
                log.warning("Scaling event poll failed: %s", exc)
            self.stop_event.wait(SCALE_POLL_INTERVAL_SECONDS)


class AdaptiveEvidencePoller(threading.Thread):
    """Persist bounded adaptive state without entering the SQL response path."""

    def __init__(self, repository: EvidenceRepository, stop_event: threading.Event):
        super().__init__(name="evidence-adaptive-poller", daemon=True)
        self.repository = repository
        self.stop_event = stop_event
        self.available = False
        self.last_error = ""

    @staticmethod
    def _get(path: str) -> dict[str, Any]:
        response = requests.get(
            f"{SESSION_MODULE_URL}{path}", timeout=POLL_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise ValueError("session-module evidence response must be an object")
        return value

    def collect_once(self) -> None:
        states = self._get("/state/sessions?limit=100").get("sessions", [])
        if not isinstance(states, list):
            raise ValueError("session-module state listing is invalid")
        for state in states:
            if not isinstance(state, dict):
                continue
            session_id = bounded_text(state.get("session_id"), 512).strip()
            if not session_id:
                continue
            state_digest = stable_id(
                "session-state",
                json.dumps(state, sort_keys=True, separators=(",", ":"), default=str),
            )
            self.repository.ingest_artifact(
                session_id,
                "session_state",
                f"SS-{state_digest[:24]}",
                state,
                state.get("updated_at") or state.get("last_seen"),
            )

        telemetry = self._get("/telemetry/decisions?limit=100").get("records", [])
        if not isinstance(telemetry, list):
            raise ValueError("session-module telemetry listing is invalid")
        for linked in telemetry:
            if not isinstance(linked, dict) or not isinstance(linked.get("decision"), dict):
                continue
            decision = linked["decision"]
            session_id = bounded_text(decision.get("session_id"), 512).strip()
            decision_id = bounded_text(decision.get("decision_id"), 128).strip()
            if not session_id or not decision_id:
                continue
            self.repository.ingest_artifact(
                session_id,
                "strategy_decision",
                decision_id,
                decision,
                decision.get("timestamp"),
            )
            reward_response = requests.get(
                f"{SESSION_MODULE_URL}/reward/decision/{decision_id}",
                timeout=POLL_TIMEOUT_SECONDS,
            )
            if reward_response.status_code == 404:
                continue
            reward_response.raise_for_status()
            reward = reward_response.json()
            if not isinstance(reward, dict):
                continue
            reward_digest = stable_id(
                "strategy-reward",
                json.dumps(reward, sort_keys=True, separators=(",", ":"), default=str),
            )
            self.repository.ingest_artifact(
                session_id,
                "strategy_reward",
                f"RW-{reward_digest[:24]}",
                reward,
                decision.get("timestamp"),
            )

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.collect_once()
                self.available = True
                self.last_error = ""
            except Exception as exc:
                self.available = False
                self.last_error = str(exc)
                log.warning("Adaptive evidence poll failed: %s", exc)
            self.stop_event.wait(ADAPTIVE_POLL_INTERVAL_SECONDS)


class Runtime:
    def __init__(self):
        self.redis = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        self.redis.ping()
        self.repository = EvidenceRepository(self.redis)
        self.stop_event = threading.Event()
        self.consumer = EvidenceConsumer(self.repository, self.stop_event)
        self.poller = ScalingEventPoller(self.repository, self.stop_event)
        self.adaptive_poller = AdaptiveEvidencePoller(self.repository, self.stop_event)

    def start(self) -> None:
        self.consumer.start()
        self.poller.start()
        self.adaptive_poller.start()

    def close(self) -> None:
        self.stop_event.set()
        self.consumer.close()
        self.consumer.join(timeout=3)
        self.poller.join(timeout=3)
        self.adaptive_poller.join(timeout=3)
        self.redis.close()


class AIReportLink(BaseModel):
    report_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=512)
    generated_at: str = ""
    risk_level: str = ""
    summary: str = ""


class EvidenceArtifactLink(BaseModel):
    session_id: str = Field(min_length=1, max_length=512)
    artifact_type: str = Field(min_length=1, max_length=64)
    artifact_id: str = Field(min_length=1, max_length=128)
    timestamp: str = Field(default="", max_length=128)
    payload: dict[str, Any]


runtime: Runtime | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global runtime
    runtime = Runtime()
    runtime.start()
    try:
        yield
    finally:
        runtime.close()
        runtime = None


app = FastAPI(title="Capstone Evidence Store", version="1.0.0", lifespan=lifespan)


def require_runtime() -> Runtime:
    if runtime is None:
        raise HTTPException(status_code=503, detail="evidence store is not initialised")
    return runtime


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "timestamp": utc_now()}


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    active = require_runtime()
    try:
        redis_ok = bool(active.redis.ping())
    except Exception:
        redis_ok = False
    ready = (
        redis_ok
        and active.consumer.connected
        and active.poller.available
        and active.adaptive_poller.available
    )
    return {
        "ready": ready,
        "timestamp": utc_now(),
        "dependencies": {
            "redis": "ok" if redis_ok else "unavailable",
            "redpanda": "ok" if active.consumer.connected else active.consumer.last_error or "connecting",
            "scaling_agent": "ok" if active.poller.available else active.poller.last_error or "connecting",
            "session_module": (
                "ok"
                if active.adaptive_poller.available
                else active.adaptive_poller.last_error or "connecting"
            ),
        },
    }


@app.get("/evidence/session/{session_id}")
def get_evidence(session_id: str) -> dict[str, Any]:
    record = require_runtime().repository.get_session(session_id)
    if record is None:
        raise HTTPException(status_code=404, detail="session evidence not found")
    return record


@app.get("/evidence/sessions")
def list_evidence(limit: int = Query(default=20, ge=1, le=100)) -> dict[str, Any]:
    sessions = require_runtime().repository.list_sessions(limit)
    return {"count": len(sessions), "sessions": sessions}


@app.post("/evidence/report", status_code=201)
def link_ai_report(report: AIReportLink) -> dict[str, Any]:
    stored = require_runtime().repository.ingest_ai_report(report.model_dump())
    return {
        "stored": stored,
        "report_id": report.report_id,
        "session_id": report.session_id,
    }


@app.post("/evidence/artifact", status_code=201)
def link_evidence_artifact(link: EvidenceArtifactLink) -> dict[str, Any]:
    try:
        stored = require_runtime().repository.ingest_artifact(
            link.session_id,
            link.artifact_type,
            link.artifact_id,
            link.payload,
            link.timestamp,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "stored": stored,
        "artifact_type": link.artifact_type,
        "artifact_id": link.artifact_id,
        "session_id": link.session_id,
    }
