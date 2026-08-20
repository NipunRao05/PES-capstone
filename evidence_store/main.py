from __future__ import annotations

import hashlib
import hmac
import json
import logging
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
POLL_TIMEOUT_SECONDS = float(os.getenv("POLL_TIMEOUT_SECONDS", "2"))
SCALE_POLL_INTERVAL_SECONDS = float(os.getenv("SCALE_POLL_INTERVAL_SECONDS", "2"))
EVIDENCE_TTL_SECONDS = int(os.getenv("EVIDENCE_TTL_SECONDS", str(30 * 24 * 60 * 60)))
MAX_QUERY_EVENTS = int(os.getenv("MAX_QUERY_EVENTS", "500"))
MAX_STAGE_EVENTS = int(os.getenv("MAX_STAGE_EVENTS", "100"))
MAX_TEXT_LENGTH = int(os.getenv("MAX_TEXT_LENGTH", "16384"))

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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bounded_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:limit]


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


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


class EvidenceRepository:
    def __init__(self, client: redis.Redis):
        self.client = client
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
            self._child_key(session_id, "scaling_events"),
            self._child_key(session_id, "ai_reports"),
            self._child_key(session_id, "event_ids"),
        ]
        pipe = self.client.pipeline(transaction=False)
        for key in keys:
            pipe.expire(key, EVIDENCE_TTL_SECONDS)
        pipe.execute()

    def _touch(self, session_id: str, payload: dict[str, Any], timestamp: str) -> None:
        key = self._record_key(session_id)
        source_ip = payload.get("client_ip") or payload.get("source_ip")
        protocol = bounded_text(payload.get("protocol"), 32).lower()
        mapping = {
            "schema_version": "1",
            "session_id": session_id,
            "last_seen": timestamp,
        }
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
        pipe.hsetnx(key, "first_seen", timestamp)
        pipe.zadd(SESSION_INDEX, {session_id: time.time()})
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

        timestamp = bounded_text(
            payload.get("timestamp") or payload.get("timestamp_closed") or payload.get("created_at"),
            128,
        ) or utc_now()
        event_id = stable_id("kafka", topic, partition, offset, session_id)
        self._touch(session_id, payload, timestamp)

        if topic in {"mysql-query-events", "pg-query-events"}:
            query = {
                "event_id": event_id,
                "timestamp": timestamp,
                "protocol": bounded_text(payload.get("protocol"), 32).lower(),
                "database": bounded_text(payload.get("database"), 256),
                "fingerprint": bounded_text(payload.get("fingerprint"), 512),
                "query_raw": redact_query(payload.get("query_raw")),
                "query_normalized": redact_query(payload.get("query_normalized")),
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

        self._expire_session_keys(session_id)
        return True

    def ingest_scale_event(self, payload: dict[str, Any]) -> bool:
        session_id = bounded_text(payload.get("session_id"), 512).strip()
        if not session_id or session_id.startswith("metric-pressure-"):
            return False
        timestamp = bounded_text(payload.get("timestamp"), 128) or utc_now()
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
        generated_at = bounded_text(payload.get("generated_at"), 128) or utc_now()
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

    def _load_list(self, session_id: str, suffix: str) -> list[dict[str, Any]]:
        values = self.client.lrange(self._child_key(session_id, suffix), 0, -1)
        return [item for item in (safe_json(value, None) for value in values) if isinstance(item, dict)]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        record = self.client.hgetall(self._record_key(session_id))
        if not record:
            return None
        queries = self._load_list(session_id, "queries")
        session_events = self._load_list(session_id, "session_events")
        mitre_events = self._load_list(session_id, "mitre_events")
        scaling_events = self._load_list(session_id, "scaling_events")
        ai_reports = self._load_list(session_id, "ai_reports")
        latest_query = queries[-1] if queries else {}
        techniques = safe_json(record.get("mitre_techniques"), [])
        result = {
            "schema_version": int(record.get("schema_version", "1")),
            "session_id": record.get("session_id", session_id),
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
            "connection_events": session_events,
            "mitre_events": mitre_events,
            "scaling_events": scaling_events,
            "ai_reports": ai_reports,
        }
        result["trace"] = {
            "connection": bool(session_events),
            "query": bool(queries),
            "mitre": bool(mitre_events),
            "scaling": bool(scaling_events),
            "ai_report": bool(ai_reports),
            "complete": all(
                [session_events, queries, mitre_events, scaling_events, ai_reports]
            ),
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
                    value_deserializer=lambda value: json.loads(value.decode("utf-8")),
                    consumer_timeout_ms=1000,
                )
                self.connected = True
                self.last_error = ""
                log.info("Evidence consumer subscribed to %s", ",".join(KAFKA_TOPICS))
                while not self.stop_event.is_set():
                    for message in self.consumer:
                        if self.stop_event.is_set():
                            break
                        if not isinstance(message.value, dict):
                            log.warning("Ignoring non-object evidence event from %s", message.topic)
                            continue
                        try:
                            self.repository.ingest_kafka(
                                message.topic,
                                message.value,
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
                if self.consumer:
                    self.consumer.close()
            except Exception as exc:
                self.connected = False
                self.last_error = str(exc)
                log.error("Evidence consumer error: %s", exc)
                self.stop_event.wait(2)

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

    def start(self) -> None:
        self.consumer.start()
        self.poller.start()

    def close(self) -> None:
        self.stop_event.set()
        self.consumer.close()
        self.consumer.join(timeout=3)
        self.poller.join(timeout=3)
        self.redis.close()


class AIReportLink(BaseModel):
    report_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=512)
    generated_at: str = ""
    risk_level: str = ""
    summary: str = ""


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
    ready = redis_ok and active.consumer.connected and active.poller.available
    return {
        "ready": ready,
        "timestamp": utc_now(),
        "dependencies": {
            "redis": "ok" if redis_ok else "unavailable",
            "redpanda": "ok" if active.consumer.connected else active.consumer.last_error or "connecting",
            "scaling_agent": "ok" if active.poller.available else active.poller.last_error or "connecting",
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
