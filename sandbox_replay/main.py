from __future__ import annotations

import json
import hashlib
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
from psycopg import sql


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
POSTGRES_ADMIN_USER = os.getenv("SANDBOX_POSTGRES_ADMIN_USER", "postgres")
POSTGRES_ADMIN_PASSWORD = os.getenv("SANDBOX_POSTGRES_ADMIN_PASSWORD", "")
MYSQL_HOST = os.getenv("SANDBOX_MYSQL_HOST", "sandbox-mysql")
MYSQL_PORT = int(os.getenv("SANDBOX_MYSQL_PORT", "3306"))
MYSQL_DATABASE = os.getenv("SANDBOX_MYSQL_DATABASE", "sandboxdb")
MYSQL_USER = os.getenv("SANDBOX_MYSQL_USER", "replay_user")
MYSQL_PASSWORD = os.getenv("SANDBOX_MYSQL_PASSWORD", "")
MYSQL_ADMIN_USER = os.getenv("SANDBOX_MYSQL_ADMIN_USER", "root")
MYSQL_ADMIN_PASSWORD = os.getenv("SANDBOX_MYSQL_ADMIN_PASSWORD", "")
QUERY_TIMEOUT_MS = max(100, int(os.getenv("REPLAY_QUERY_TIMEOUT_MS", "750")))
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "3"))
RESULT_TTL_SECONDS = int(os.getenv("REPLAY_RESULT_TTL_SECONDS", str(7 * 24 * 60 * 60)))
MAX_QUERIES_PER_REPLAY = int(os.getenv("MAX_QUERIES_PER_REPLAY", "100"))

RESULT_PREFIX = "sandbox:replay:"
SESSION_REPLAY_PREFIX = "sandbox:session:"
HARDENING_PREFIX = "sandbox:hardening:"
HARDENING_LATEST_KEY = "sandbox:hardening:latest"
SESSION_HARDENING_PREFIX = "sandbox:session:hardening:"

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
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")
SENSITIVE_OBJECT = re.compile(
    r"(?i)(api[_-]?keys?|secret|credential|password|token|backup|customer|citizen|card|patient|health)"
)
METADATA_QUERY = re.compile(r"(?i)\b(information_schema|pg_catalog)\b")


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


def stable_id(*parts: Any) -> str:
    material = "\x1f".join(bounded(part, 4096) for part in parts)
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


def query_fingerprint(finding: dict[str, Any]) -> str:
    return stable_id(finding.get("query_normalized") or finding.get("query"))


def split_object_identifier(value: Any, protocol: str) -> tuple[str, str]:
    raw = bounded(value, 256).strip().strip("`\"")
    parts = [part.strip("`\"") for part in raw.split(".") if part]
    if len(parts) == 1:
        schema = MYSQL_DATABASE if protocol == "mysql" else "public"
        name = parts[0]
    elif len(parts) == 2:
        schema, name = parts
    else:
        raise ValueError("affected object must be an unqualified or schema-qualified table")
    if not SAFE_IDENTIFIER.fullmatch(schema) or not SAFE_IDENTIFIER.fullmatch(name):
        raise ValueError("affected object contains an unsafe identifier")
    if protocol == "mysql" and schema != MYSQL_DATABASE:
        raise ValueError("MySQL hardening fixes are restricted to the disposable sandbox database")
    if protocol == "postgres" and schema != "public":
        raise ValueError("PostgreSQL hardening fixes are restricted to the public sandbox schema")
    return schema, name


def replay_summary(replay: dict[str, Any]) -> dict[str, Any]:
    return {
        "replay_id": replay.get("replay_id"),
        "session_id": replay.get("session_id"),
        "protocol": replay.get("protocol"),
        "query_count": replay.get("query_count", 0),
        "executed_count": replay.get("executed_count", 0),
        "simulated_count": replay.get("simulated_count", 0),
        "blocked_count": replay.get("blocked_count", 0),
        "timeout_count": replay.get("timeout_count", 0),
        "failed_count": replay.get("failed_count", 0),
    }


def build_hardening_recommendations(replay: dict[str, Any]) -> list[dict[str, Any]]:
    replay_id = bounded(replay.get("replay_id"), 128)
    protocol = normalize_protocol(replay.get("protocol"))
    recommendations: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(
        finding: dict[str, Any],
        issue: str,
        severity: str,
        recommended_fix: str,
        verification_step: str,
        action_type: str,
    ) -> None:
        fingerprint = query_fingerprint(finding)
        affected = bounded(finding.get("affected_object"), 256)
        dedupe_key = stable_id(issue, affected, fingerprint)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        recommendations.append(
            {
                "recommendation_id": stable_id(replay_id, dedupe_key),
                "issue": issue,
                "evidence": {
                    "replay_id": replay_id,
                    "session_id": replay.get("session_id"),
                    "query_normalized": bounded(
                        finding.get("query_normalized") or finding.get("query")
                    ),
                    "classification": finding.get("classification"),
                    "replay_mode": finding.get("replay_mode"),
                    "would_succeed": finding.get("would_succeed"),
                },
                "affected_object": affected,
                "severity": severity,
                "recommended_fix": recommended_fix,
                "verification_step": verification_step,
                "action": {
                    "type": action_type,
                    "protocol": protocol,
                    "query_fingerprint": fingerprint,
                },
            }
        )

    findings = replay.get("findings", [])
    if not isinstance(findings, list):
        return recommendations

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        query = bounded(finding.get("query_normalized") or finding.get("query"))
        obj = bounded(finding.get("affected_object"), 256)
        outcome = finding.get("replay_mode")

        if outcome == "executed" and obj and SENSITIVE_OBJECT.search(obj):
            add(
                finding,
                "Sensitive-looking table was readable by the sandbox replay role",
                "high",
                f"Revoke direct SELECT access to {obj} from the exposed role and grant access only through a narrowly scoped role or view.",
                "Replay the same captured query and confirm that the sandbox role receives an access-denied error.",
                "revoke_select",
            )

        if outcome == "executed" and METADATA_QUERY.search(query):
            add(
                finding,
                "Database metadata enumeration succeeded",
                "medium",
                "Reduce object grants so the exposed role can see only required schemas and tables; review metadata visibility for the target database engine.",
                "Replay the enumeration and confirm that restricted objects are no longer disclosed.",
                "manual_metadata_review",
            )

        if outcome == "timed_out":
            add(
                finding,
                "Resource-intensive query reached the sandbox statement timeout",
                "medium",
                f"Keep the untrusted-role statement timeout at or below {QUERY_TIMEOUT_MS} ms and add workload limits for expensive reads.",
                "Replay the same query and confirm it is terminated by the configured timeout.",
                "verify_timeout_control",
            )

        if outcome == "blocked" and finding.get("classification") in {
            "destructive_or_mutating",
            "unsafe_multi_statement",
        }:
            add(
                finding,
                "Destructive or mutating query was blocked by replay policy",
                "high",
                "Retain deny-by-default replay controls and revoke DROP, DELETE, UPDATE, ALTER, and related write privileges from exposed roles.",
                "Replay the same captured query and confirm it remains blocked before database execution.",
                "verify_policy_control",
            )

    return recommendations


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


class HardeningRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


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

    def save_hardening(self, report: dict[str, Any]) -> None:
        report_id = report["hardening_report_id"]
        session_id = report["session_id"]
        report_key = f"{HARDENING_PREFIX}{report_id}"
        session_key = f"{SESSION_HARDENING_PREFIX}{session_id}:reports"
        payload = json.dumps(report, separators=(",", ":"), default=str)
        pipe = self.client.pipeline(transaction=False)
        pipe.setex(report_key, RESULT_TTL_SECONDS, payload)
        pipe.setex(HARDENING_LATEST_KEY, RESULT_TTL_SECONDS, report_id)
        pipe.lpush(session_key, report_id)
        pipe.ltrim(session_key, 0, 99)
        pipe.expire(session_key, RESULT_TTL_SECONDS)
        pipe.execute()

    def get_hardening(self, report_id: str) -> dict[str, Any] | None:
        raw = self.client.get(f"{HARDENING_PREFIX}{report_id}")
        if not raw:
            return None
        try:
            report = json.loads(raw)
            return report if isinstance(report, dict) else None
        except (TypeError, ValueError):
            return None

    def get_latest_hardening(self) -> dict[str, Any] | None:
        report_id = self.client.get(HARDENING_LATEST_KEY)
        return self.get_hardening(report_id) if report_id else None


class ReplayEngine:
    def __init__(self, store: ReplayStore):
        self.store = store
        self.replay_slots = threading.BoundedSemaphore(4)
        self.hardening_lock = threading.Lock()

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

    def _postgres_admin_ready(self) -> bool:
        try:
            with psycopg.connect(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                dbname=POSTGRES_DATABASE,
                user=POSTGRES_ADMIN_USER,
                password=POSTGRES_ADMIN_PASSWORD,
                connect_timeout=2,
            ) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            return True
        except Exception:
            return False

    def _mysql_admin_ready(self) -> bool:
        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                database=MYSQL_DATABASE,
                user=MYSQL_ADMIN_USER,
                password=MYSQL_ADMIN_PASSWORD,
                connect_timeout=2,
                read_timeout=2,
                write_timeout=2,
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
            "postgres_replay": self._postgres_ready(),
            "mysql_replay": self._mysql_ready(),
            "postgres_hardening_admin": self._postgres_admin_ready(),
            "mysql_hardening_admin": self._mysql_admin_ready(),
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

    def _revoke_postgres_select(self, affected_object: str) -> dict[str, Any]:
        schema, name = split_object_identifier(affected_object, "postgres")
        with psycopg.connect(
            host=POSTGRES_HOST,
            port=POSTGRES_PORT,
            dbname=POSTGRES_DATABASE,
            user=POSTGRES_ADMIN_USER,
            password=POSTGRES_ADMIN_PASSWORD,
            connect_timeout=2,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT has_table_privilege(%s, %s, 'SELECT')",
                    (POSTGRES_USER, f"{schema}.{name}"),
                )
                had_privilege = bool(cursor.fetchone()[0])
                if had_privilege:
                    cursor.execute(
                        sql.SQL("REVOKE SELECT ON TABLE {} FROM {}").format(
                            sql.Identifier(schema, name),
                            sql.Identifier(POSTGRES_USER),
                        )
                    )
        return {
            "action": "revoke_select",
            "protocol": "postgres",
            "affected_object": f"{schema}.{name}",
            "status": "applied" if had_privilege else "already_applied",
        }

    def _revoke_mysql_select(self, affected_object: str) -> dict[str, Any]:
        schema, name = split_object_identifier(affected_object, "mysql")
        if not SAFE_IDENTIFIER.fullmatch(MYSQL_USER):
            raise ValueError("configured MySQL replay user is not a safe identifier")
        connection = pymysql.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            database=MYSQL_DATABASE,
            user=MYSQL_ADMIN_USER,
            password=MYSQL_ADMIN_PASSWORD,
            connect_timeout=2,
            read_timeout=2,
            write_timeout=2,
            autocommit=False,
        )
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM information_schema.table_privileges "
                    "WHERE GRANTEE=%s AND TABLE_SCHEMA=%s AND TABLE_NAME=%s "
                    "AND PRIVILEGE_TYPE='SELECT' LIMIT 1",
                    (f"'{MYSQL_USER}'@'%'", schema, name),
                )
                had_privilege = cursor.fetchone() is not None
                if had_privilege:
                    cursor.execute(
                        f"REVOKE SELECT ON `{schema}`.`{name}` FROM '{MYSQL_USER}'@'%'"
                    )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return {
            "action": "revoke_select",
            "protocol": "mysql",
            "affected_object": f"{schema}.{name}",
            "status": "applied" if had_privilege else "already_applied",
        }

    def create_hardening_report(self, replay_id: str) -> dict[str, Any]:
        replay = self.store.get(replay_id)
        if replay is None:
            raise HTTPException(status_code=404, detail="replay result not found")
        recommendations = build_hardening_recommendations(replay)
        report = {
            "hardening_report_id": str(uuid.uuid4()),
            "source_replay_id": replay_id,
            "session_id": replay.get("session_id"),
            "protocol": normalize_protocol(replay.get("protocol")),
            "generated_at": utc_now(),
            "status": "recommendations_generated",
            "before": replay_summary(replay),
            "recommendation_count": len(recommendations),
            "recommendations": recommendations,
            "verification": None,
        }
        self.store.save_hardening(report)
        return report

    def verify_hardening_report(self, report_id: str) -> dict[str, Any]:
        if not self.hardening_lock.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="hardening verification already in progress")
        try:
            report = self.store.get_hardening(report_id)
            if report is None:
                raise HTTPException(status_code=404, detail="hardening report not found")
            if report.get("verification") is not None:
                self.store.save_hardening(report)
                return report

            before = self.store.get(bounded(report.get("source_replay_id"), 128))
            if before is None:
                raise HTTPException(status_code=409, detail="source replay result expired")

            protocol = normalize_protocol(report.get("protocol"))
            applied_fixes: list[dict[str, Any]] = []
            for recommendation in report.get("recommendations", []):
                action = recommendation.get("action", {})
                if action.get("type") != "revoke_select":
                    continue
                affected = bounded(recommendation.get("affected_object"), 256)
                try:
                    applied = (
                        self._revoke_postgres_select(affected)
                        if protocol == "postgres"
                        else self._revoke_mysql_select(affected)
                    )
                    applied["recommendation_id"] = recommendation.get("recommendation_id")
                    applied_fixes.append(applied)
                except Exception as exc:
                    applied_fixes.append(
                        {
                            "action": "revoke_select",
                            "protocol": protocol,
                            "affected_object": affected,
                            "status": "failed",
                            "recommendation_id": recommendation.get("recommendation_id"),
                            "reason": bounded(exc, 512),
                        }
                    )

            after = self.replay(bounded(report.get("session_id"), 256), "execute")
            after_by_fingerprint = {
                query_fingerprint(finding): finding
                for finding in after.get("findings", [])
                if isinstance(finding, dict)
            }

            verification_results: list[dict[str, Any]] = []
            for recommendation in report.get("recommendations", []):
                action = recommendation.get("action", {})
                action_type = action.get("type")
                after_finding = after_by_fingerprint.get(action.get("query_fingerprint"))
                after_outcome = after_finding.get("replay_mode") if after_finding else "missing"
                verified = False
                verification_status = "failed"

                if action_type == "revoke_select":
                    reason = bounded((after_finding or {}).get("reason"), 512).lower()
                    verified = after_outcome == "failed" and any(
                        marker in reason
                        for marker in ("permission denied", "command denied", "access denied", "not authorized")
                    )
                    verification_status = "verified" if verified else "failed"
                elif action_type == "verify_timeout_control":
                    verified = after_outcome == "timed_out"
                    verification_status = "verified" if verified else "failed"
                elif action_type == "verify_policy_control":
                    verified = after_outcome == "blocked"
                    verification_status = "verified" if verified else "failed"
                elif action_type == "manual_metadata_review":
                    verification_status = "manual_follow_up_required"

                verification_results.append(
                    {
                        "recommendation_id": recommendation.get("recommendation_id"),
                        "action": action_type,
                        "affected_object": recommendation.get("affected_object"),
                        "before_outcome": recommendation.get("evidence", {}).get("replay_mode"),
                        "after_outcome": after_outcome,
                        "verified": verified,
                        "status": verification_status,
                    }
                )

            automated = [
                item
                for item in verification_results
                if item["status"] != "manual_follow_up_required"
            ]
            manual_count = len(verification_results) - len(automated)
            verified_count = sum(1 for item in automated if item["verified"])
            all_automated_verified = bool(automated) and verified_count == len(automated)
            if not verification_results:
                status = "no_recommendations"
            elif not automated and manual_count:
                status = "manual_follow_up_required"
            elif all_automated_verified and manual_count:
                status = "verified_with_manual_follow_up"
            elif all_automated_verified:
                status = "verified"
            else:
                status = "verification_failed"

            report["status"] = status
            report["verification"] = {
                "verified_at": utc_now(),
                "before": replay_summary(before),
                "after": replay_summary(after),
                "applied_fix_count": sum(
                    1 for item in applied_fixes if item.get("status") == "applied"
                ),
                "applied_fixes": applied_fixes,
                "automated_recommendation_count": len(automated),
                "verified_count": verified_count,
                "manual_follow_up_count": manual_count,
                "results": verification_results,
            }
            self.store.save_hardening(report)
            return report
        finally:
            self.hardening_lock.release()

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
            "sandbox_postgres_replay": "ok" if databases["postgres_replay"] else "unavailable",
            "sandbox_mysql_replay": "ok" if databases["mysql_replay"] else "unavailable",
            "sandbox_postgres_hardening_admin": (
                "ok" if databases["postgres_hardening_admin"] else "unavailable"
            ),
            "sandbox_mysql_hardening_admin": (
                "ok" if databases["mysql_hardening_admin"] else "unavailable"
            ),
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


@app.post("/hardening/report/{replay_id}")
def create_hardening_report(replay_id: str, _: HardeningRequest) -> dict[str, Any]:
    return require_runtime().engine.create_hardening_report(replay_id)


@app.post("/hardening/verify/{report_id}")
def verify_hardening_report(report_id: str, _: HardeningRequest) -> dict[str, Any]:
    return require_runtime().engine.verify_hardening_report(report_id)


@app.get("/hardening/report/{report_id}")
def hardening_report(report_id: str) -> dict[str, Any]:
    report = require_runtime().store.get_hardening(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="hardening report not found")
    return report


@app.get("/hardening/latest")
def latest_hardening_report() -> dict[str, Any]:
    report = require_runtime().store.get_latest_hardening()
    if report is None:
        return {"available": False}
    return {"available": True, **report}
