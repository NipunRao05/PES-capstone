from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Literal

import psycopg
import pymysql
import redis
import requests
import sqlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("sandbox-replay")

EVIDENCE_STORE_URL = os.getenv("EVIDENCE_STORE_URL", "http://evidence-store:8011")
REDIS_HOST = os.getenv("REDIS_HOST", "redis-mitre")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
POSTGRES_HOST = os.getenv("SANDBOX_POSTGRES_HOST", "sandbox-postgres")
POSTGRES_PORT = int(os.getenv("SANDBOX_POSTGRES_PORT", "5432"))
POSTGRES_DATABASE = os.getenv("SANDBOX_POSTGRES_DATABASE", "sandboxdb")
POSTGRES_USER = os.getenv("SANDBOX_POSTGRES_USER", "replay_user")
POSTGRES_PASSWORD = os.getenv("SANDBOX_POSTGRES_PASSWORD", "")
MYSQL_HOST = os.getenv("SANDBOX_MYSQL_HOST", "sandbox-mysql")
MYSQL_PORT = int(os.getenv("SANDBOX_MYSQL_PORT", "3306"))
MYSQL_DATABASE = os.getenv("SANDBOX_MYSQL_DATABASE", "sandboxdb")
MYSQL_USER = os.getenv("SANDBOX_MYSQL_USER", "replay_user")
MYSQL_PASSWORD = os.getenv("SANDBOX_MYSQL_PASSWORD", "")
QUERY_TIMEOUT_MS = max(100, int(os.getenv("REPLAY_QUERY_TIMEOUT_MS", "750")))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "3"))
RESULT_TTL_SECONDS = int(os.getenv("REPLAY_RESULT_TTL_SECONDS", str(7 * 24 * 60 * 60)))
MAX_QUERIES_PER_REPLAY = int(os.getenv("MAX_QUERIES_PER_REPLAY", "100"))

RESULT_PREFIX = "sandbox:replay:"
SESSION_REPLAY_PREFIX = "sandbox:session:"

MUTATING_KEYWORDS = {
    "ALTER",
    "CALL",
    "COPY",
    "CREATE",
    "DELETE",
    "DO",
    "DROP",
    "EXECUTE",
    "GRANT",
    "INSERT",
    "LOAD",
    "MERGE",
    "RENAME",
    "REPLACE",
    "REVOKE",
    "SET",
    "TRUNCATE",
    "UPDATE",
}
ALLOWED_BY_PROTOCOL = {
    "postgres": {"SELECT"},
    "mysql": {"SELECT", "SHOW", "DESCRIBE", "DESC"},
}
FORBIDDEN_PATTERNS = (
    re.compile(r"(?i)\binto\s+(outfile|dumpfile)\b"),
    re.compile(r"(?i)\bload_file\s*\("),
    re.compile(r"(?i)\bpg_(read|write|ls|stat|logdir|file)_\w*\s*\("),
    re.compile(r"(?i)\bdblink\s*\("),
    re.compile(r"(?i)\blo_(import|export)\s*\("),
    re.compile(r"(?i)\bcopy\b"),
    re.compile(r"(?i)\bbenchmark\s*\("),
)
TIMEOUT_PATTERNS = (
    re.compile(r"(?i)\bpg_sleep\s*\("),
    re.compile(r"(?i)\bsleep\s*\("),
)
OBJECT_PATTERN = re.compile(
    r"(?i)\b(?:from|join|update|into|table|describe)\s+([`\"\w.]+)"
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bounded(value: Any, limit: int = 16384) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "")[:limit]


def normalize_protocol(value: Any) -> str:
    protocol = bounded(value, 32).strip().lower()
    if protocol in {"pg", "postgresql"} or protocol.startswith("postgres"):
        return "postgres"
    if protocol.startswith("mysql"):
        return "mysql"
    return protocol


def affected_object(query: str) -> str:
    match = OBJECT_PATTERN.search(query)
    return match.group(1).strip("`\"") if match else ""


def first_keyword(statement: str) -> str:
    parsed = sqlparse.parse(statement)
    if not parsed:
        return ""
    token = parsed[0].token_first(skip_ws=True, skip_cm=True)
    return token.normalized.upper() if token is not None else ""


def classify_query(query: str, protocol: str) -> dict[str, Any]:
    clean_query = bounded(query).strip()
    statements = [part.strip() for part in sqlparse.split(clean_query) if part.strip()]
    obj = affected_object(clean_query)

    if len(statements) != 1:
        return {
            "classification": "unsafe_multi_statement",
            "allowed": False,
            "severity": "critical",
            "affected_object": obj,
            "reason": "Multiple SQL statements are never replayed.",
            "recommended_countermeasure": "Reject multi-statement execution and disable it in exposed database roles.",
        }

    statement = statements[0]
    keyword = first_keyword(statement)
    if keyword in MUTATING_KEYWORDS:
        return {
            "classification": "destructive_or_mutating",
            "allowed": False,
            "severity": "critical" if keyword in {"DROP", "TRUNCATE", "ALTER"} else "high",
            "affected_object": obj,
            "reason": f"{keyword or 'Unknown'} statements are blocked by the replay policy.",
            "recommended_countermeasure": f"Ensure the exposed role cannot execute {keyword or 'mutating'} statements.",
        }

    if keyword == "WITH":
        return {
            "classification": "unsafe_common_table_expression",
            "allowed": False,
            "severity": "high",
            "affected_object": obj,
            "reason": "Common-table expressions may conceal mutating statements and are blocked by default.",
            "recommended_countermeasure": "Review CTE behavior manually before adding a narrowly scoped allowlist rule.",
        }

    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(statement):
            return {
                "classification": "unsafe_database_function",
                "allowed": False,
                "severity": "critical",
                "affected_object": obj,
                "reason": "The query contains a file, external-access, or privileged database capability.",
                "recommended_countermeasure": "Revoke file and external-access privileges from the exposed database role.",
            }

    allowed_keywords = ALLOWED_BY_PROTOCOL.get(protocol, set())
    if keyword not in allowed_keywords:
        return {
            "classification": "unknown_unsafe",
            "allowed": False,
            "severity": "high",
            "affected_object": obj,
            "reason": f"The leading keyword {keyword or 'UNKNOWN'} is not allowlisted for {protocol or 'unknown protocol'}.",
            "recommended_countermeasure": "Keep deny-by-default SQL controls and review this statement manually.",
        }

    resource_intensive = any(pattern.search(statement) for pattern in TIMEOUT_PATTERNS)
    return {
        "classification": "resource_intensive_read" if resource_intensive else "read_only",
        "allowed": True,
        "severity": "medium" if resource_intensive else "info",
        "affected_object": obj,
        "reason": (
            "Read-only query contains an intentional delay and will run with a strict timeout."
            if resource_intensive
            else "Statement is on the protocol-specific read-only allowlist."
        ),
        "recommended_countermeasure": (
            "Enforce a low statement timeout for untrusted database roles."
            if resource_intensive
            else "Retain least-privilege read-only grants and monitor object access."
        ),
    }


def is_timeout_error(exc: Exception) -> bool:
    text = str(exc).lower()
    if "statement timeout" in text or "query execution was interrupted" in text:
        return True
    if isinstance(exc, pymysql.MySQLError) and exc.args:
        return exc.args[0] in {1317, 3024}
    return isinstance(exc, psycopg.errors.QueryCanceled)


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["execute", "simulate"] = "execute"


class ReplayStore:
    def __init__(self, client: redis.Redis):
        self.client = client

    def save(self, result: dict[str, Any]) -> None:
        replay_id = result["replay_id"]
        session_id = result["session_id"]
        result_key = f"{RESULT_PREFIX}{replay_id}"
        session_key = f"{SESSION_REPLAY_PREFIX}{session_id}:replays"
        pipe = self.client.pipeline(transaction=False)
        pipe.setex(result_key, RESULT_TTL_SECONDS, json.dumps(result, separators=(",", ":"), default=str))
        pipe.lpush(session_key, replay_id)
        pipe.ltrim(session_key, 0, 99)
        pipe.expire(session_key, RESULT_TTL_SECONDS)
        pipe.execute()

    def get(self, replay_id: str) -> dict[str, Any] | None:
        raw = self.client.get(f"{RESULT_PREFIX}{replay_id}")
        if not raw:
            return None
        try:
            result = json.loads(raw)
            return result if isinstance(result, dict) else None
        except (TypeError, ValueError):
            return None


class ReplayEngine:
    def __init__(self, store: ReplayStore):
        self.store = store
        self.replay_slots = threading.BoundedSemaphore(4)

    def fetch_evidence(self, session_id: str) -> dict[str, Any]:
        response = requests.get(
            f"{EVIDENCE_STORE_URL}/evidence/session/{session_id}",
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="session evidence not found")
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise HTTPException(status_code=502, detail="invalid evidence-store response")
        return payload

    def _postgres_ready(self) -> bool:
        try:
            with psycopg.connect(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                dbname=POSTGRES_DATABASE,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                connect_timeout=2,
                options=f"-c statement_timeout={QUERY_TIMEOUT_MS} -c default_transaction_read_only=on",
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            return True
        except Exception:
            return False

    def _mysql_ready(self) -> bool:
        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                database=MYSQL_DATABASE,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                connect_timeout=2,
                read_timeout=2,
                write_timeout=2,
                autocommit=False,
            )
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            finally:
                connection.close()
            return True
        except Exception:
            return False

    def readiness(self) -> dict[str, bool]:
        return {
            "postgres": self._postgres_ready(),
            "mysql": self._mysql_ready(),
        }

    def _execute_postgres(self, query: str) -> int:
        with psycopg.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            dbname=POSTGRES_DATABASE,
            user=POSTGRES_USER,
            password=POSTGRES_PASSWORD,
            connect_timeout=2,
            options=f"-c statement_timeout={QUERY_TIMEOUT_MS} -c default_transaction_read_only=on",
            autocommit=False,
        ) as connection:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(query)
                    rows = cursor.fetchmany(1) if cursor.description else []
                connection.rollback()
                return len(rows)
            except Exception:
                connection.rollback()
                raise

    def _execute_mysql(self, query: str) -> int:
        connection = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            database=MYSQL_DATABASE,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            connect_timeout=2,
            read_timeout=max(2, int(QUERY_TIMEOUT_MS / 1000) + 2),
            write_timeout=2,
            autocommit=False,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"SET SESSION MAX_EXECUTION_TIME={QUERY_TIMEOUT_MS}")
                cursor.execute("START TRANSACTION READ ONLY")
                cursor.execute(query)
                rows = cursor.fetchmany(1) if cursor.description else []
            connection.rollback()
            return len(rows)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def replay(self, session_id: str, mode: str) -> dict[str, Any]:
        if not self.replay_slots.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="replay concurrency limit reached")
        try:
            evidence = self.fetch_evidence(session_id)
            protocol = normalize_protocol(evidence.get("protocol"))
            if protocol not in ALLOWED_BY_PROTOCOL:
                raise HTTPException(status_code=400, detail="unsupported session protocol")
            queries = evidence.get("queries", [])
            if not isinstance(queries, list) or not queries:
                raise HTTPException(status_code=422, detail="session has no captured queries")

            replay_id = str(uuid.uuid4())
            result: dict[str, Any] = {
                "replay_id": replay_id,
                "session_id": session_id,
                "protocol": protocol,
                "requested_mode": mode,
                "started_at": utc_now(),
                "query_count": min(len(queries), MAX_QUERIES_PER_REPLAY),
                "executed_count": 0,
                "simulated_count": 0,
                "blocked_count": 0,
                "timeout_count": 0,
                "failed_count": 0,
                "truncated": len(queries) > MAX_QUERIES_PER_REPLAY,
                "findings": [],
            }

            for captured in queries[:MAX_QUERIES_PER_REPLAY]:
                if not isinstance(captured, dict):
                    continue
                query = bounded(captured.get("query_raw") or captured.get("query_normalized"))
                normalized = bounded(captured.get("query_normalized"))
                policy = classify_query(query, protocol)
                finding = {
                    "query": query,
                    "query_normalized": normalized,
                    "classification": policy["classification"],
                    "replay_mode": "blocked",
                    "would_succeed": None,
                    "severity": policy["severity"],
                    "affected_object": policy["affected_object"],
                    "reason": policy["reason"],
                    "recommended_countermeasure": policy["recommended_countermeasure"],
                }

                if not policy["allowed"]:
                    result["blocked_count"] += 1
                elif mode == "simulate":
                    finding["replay_mode"] = "simulated"
                    result["simulated_count"] += 1
                else:
                    try:
                        row_sample_count = (
                            self._execute_postgres(query)
                            if protocol == "postgres"
                            else self._execute_mysql(query)
                        )
                        finding["replay_mode"] = "executed"
                        finding["would_succeed"] = True
                        finding["row_sample_count"] = row_sample_count
                        result["executed_count"] += 1
                    except Exception as exc:
                        if is_timeout_error(exc):
                            finding["replay_mode"] = "timed_out"
                            finding["severity"] = "medium"
                            finding["reason"] = f"Sandbox query exceeded the {QUERY_TIMEOUT_MS} ms timeout."
                            finding["recommended_countermeasure"] = "Set a strict statement timeout for the exposed role."
                            result["timeout_count"] += 1
                        else:
                            finding["replay_mode"] = "failed"
                            finding["would_succeed"] = False
                            finding["reason"] = f"Sandbox execution failed: {bounded(exc, 512)}"
                            result["failed_count"] += 1
                result["findings"].append(finding)

            result["completed_at"] = utc_now()
            self.store.save(result)
            return result
        finally:
            self.replay_slots.release()


class Runtime:
    def __init__(self):
        self.redis = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        self.redis.ping()
        self.store = ReplayStore(self.redis)
        self.engine = ReplayEngine(self.store)

    def close(self) -> None:
        self.redis.close()


runtime: Runtime | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global runtime
    runtime = Runtime()
    try:
        yield
    finally:
        runtime.close()
        runtime = None


app = FastAPI(title="Capstone Sandbox Replay Engine", version="1.0.0", lifespan=lifespan)


def require_runtime() -> Runtime:
    if runtime is None:
        raise HTTPException(status_code=503, detail="sandbox replay engine is not initialised")
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
    try:
        evidence_response = requests.get(f"{EVIDENCE_STORE_URL}/readyz", timeout=HTTP_TIMEOUT_SECONDS)
        evidence_ok = evidence_response.ok and evidence_response.json().get("ready") is True
    except Exception:
        evidence_ok = False
    databases = active.engine.readiness()
    ready = redis_ok and evidence_ok and all(databases.values())
    return {
        "ready": ready,
        "timestamp": utc_now(),
        "dependencies": {
            "redis": "ok" if redis_ok else "unavailable",
            "evidence_store": "ok" if evidence_ok else "unavailable",
            "sandbox_postgres": "ok" if databases["postgres"] else "unavailable",
            "sandbox_mysql": "ok" if databases["mysql"] else "unavailable",
        },
        "safety": {
            "captured_evidence_only": True,
            "read_only_allowlist": True,
            "query_timeout_ms": QUERY_TIMEOUT_MS,
            "sandbox_databases": [POSTGRES_DATABASE, MYSQL_DATABASE],
        },
    }


@app.post("/replay/session/{session_id}")
def replay_session(session_id: str, request: ReplayRequest) -> dict[str, Any]:
    try:
        return require_runtime().engine.replay(session_id, request.mode)
    except HTTPException:
        raise
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"evidence store unavailable: {bounded(exc, 256)}") from exc


@app.get("/replay/result/{replay_id}")
def replay_result(replay_id: str) -> dict[str, Any]:
    result = require_runtime().store.get(replay_id)
    if result is None:
        raise HTTPException(status_code=404, detail="replay result not found")
    return result
