"""
api.py — FastAPI deception engine.

The proxy shaper calls POST /decide for every intercepted query.
Returns a DecisionResponse telling the proxy whether to:
  - passthrough: forward to real backend
  - fake: return generated fake rows
  - block: return an error
  - delay: inject latency then passthrough

All fake data is seeded per session_id so responses are consistent
across multiple queries in the same session (consistency probes pass).
"""

from __future__ import annotations
from principal_runtime import install as install_principals, principal_seed

import dataclasses
import json
import logging
import math
import os
import random
import re
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace

import redis
import uvicorn
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from exposure import ExposureTracker
from generator import DataGenerator
from models import DecisionRequest, DecisionResponse
from mutation_store import MutationStore
from schema_loader import SchemaLoader
from strategy_registry import StrategyRegistry
from policy_guard import POLICY_VERSION, PolicyGuard
from strategy_agent import RULE_POLICY_VERSION, RuleOnlyStrategyAgent
from persona import (
    DEFAULT_DATABASE, DEFAULT_SCHEMA, MYSQL_VERSION, MYSQL_VERSION_COMMENT,
    POSTGRES_SERVER_VERSION, POSTGRES_VERSION,
)

log = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))

# /decide request validation limits. These are defensive API limits; the
# proxies already apply their own query-size guard before calling /decide.
DECIDE_MAX_QUERY_BYTES = int(os.environ.get("DECIDE_MAX_QUERY_BYTES", "65536"))
DECIDE_MAX_SESSION_ID_BYTES = int(os.environ.get("DECIDE_MAX_SESSION_ID_BYTES", "256"))
DECIDE_MAX_DATABASE_BYTES = int(os.environ.get("DECIDE_MAX_DATABASE_BYTES", "128"))
DECIDE_MIN_DECEPTION_LEVEL = int(os.environ.get("DECIDE_MIN_DECEPTION_LEVEL", "0"))
DECIDE_MAX_DECEPTION_LEVEL = int(os.environ.get("DECIDE_MAX_DECEPTION_LEVEL", "4"))
DECIDE_MIN_RISK_SCORE = float(os.environ.get("DECIDE_MIN_RISK_SCORE", "0"))
DECIDE_MAX_RISK_SCORE = float(os.environ.get("DECIDE_MAX_RISK_SCORE", "100"))

# /decide rate limiting. Redis-backed counters are used so this remains safe
# when deception-engine later runs with multiple replicas. Set a limit to 0 to
# disable that individual scope.
DECIDE_RATE_LIMIT_ENABLED = os.environ.get("DECIDE_RATE_LIMIT_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
DECIDE_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("DECIDE_RATE_LIMIT_WINDOW_SECONDS", "60"))
DECIDE_RATE_LIMIT_PER_SESSION = int(os.environ.get("DECIDE_RATE_LIMIT_PER_SESSION", "120"))
DECIDE_RATE_LIMIT_PER_CLIENT = int(os.environ.get("DECIDE_RATE_LIMIT_PER_CLIENT", "300"))
DECIDE_RATE_LIMIT_GLOBAL = int(os.environ.get("DECIDE_RATE_LIMIT_GLOBAL", "3000"))
DECIDE_RATE_LIMIT_FAIL_OPEN = os.environ.get("DECIDE_RATE_LIMIT_FAIL_OPEN", "true").strip().lower() not in {"0", "false", "no", "off"}

# System variable banner values — override via env
BANNER_HOSTNAME       = os.environ.get("DECEPTION_HOSTNAME",        "db-prod-02")
BANNER_DATADIR        = os.environ.get("DECEPTION_DATADIR",         "/var/lib/mysql")
BANNER_VERSION_COMMENT = MYSQL_VERSION_COMMENT
BANNER_VERSION        = MYSQL_VERSION
BANNER_PORT           = os.environ.get("DECEPTION_PORT",            "3306")
POSTGRES_PORT         = os.environ.get("DECEPTION_POSTGRES_PORT",     "5432")

# Fake database list returned by SHOW DATABASES
FAKE_DATABASES = [
    "information_schema", "mysql", "performance_schema",
    "hr_production", "finance_production", "crm_production",
]

# System variable → banner value mapping (normalised fingerprint → value)
SYSTEM_VAR_MAP = {
    "select @@hostname":         BANNER_HOSTNAME,
    "select @@datadir":          BANNER_DATADIR,
    "select @@version_comment":  BANNER_VERSION_COMMENT,
    "select @@version":          BANNER_VERSION,
    "select @@global.version":   BANNER_VERSION,
    "select @@port":             BANNER_PORT,
    "select @@basedir":          "/usr",
    "select @@max_connections":  "1000",
    "select @@global.max_connections": "1000",
    "select version()":          BANNER_VERSION,
    "select @@global.secure_file_priv": "",
}

# PostgreSQL discovery queries use function/identifier names rather than @@vars
# and many clients expect protocol-native column labels. Values can be overridden
# for demos but are intentionally fake.
POSTGRES_SYSTEM_VAR_MAP = {
    "select version()":             ("version", POSTGRES_VERSION),
    "select current_database()":    ("current_database", None),
    "select current_database":      ("current_database", None),
    "select current_user":          ("current_user", None),
    "select current_user()":        ("current_user", None),
    "select session_user":          ("session_user", None),
    "select current_schema()":      ("current_schema", "public"),
    "select current_schema":        ("current_schema", "public"),
    "select inet_server_port()":    ("inet_server_port", POSTGRES_PORT),
    "show server_version":          ("server_version", POSTGRES_SERVER_VERSION),
}

# ─── App startup ──────────────────────────────────────────────────────────────

_redis_client: redis.Redis | None = None
_schema_loader: SchemaLoader | None = None
_generator: DataGenerator | None = None
_exposure: ExposureTracker | None = None
_mutations: MutationStore | None = None
_strategy_registry: StrategyRegistry = StrategyRegistry.load_with_fallback()
_policy_guard: PolicyGuard = PolicyGuard(_strategy_registry)
_strategy_agent: RuleOnlyStrategyAgent = RuleOnlyStrategyAgent(_policy_guard)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redis_client, _schema_loader, _generator, _exposure, _mutations, _strategy_registry, _policy_guard, _strategy_agent
    _redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT,
        decode_responses=True,
        socket_timeout=3,
        socket_connect_timeout=3,
    )
    _schema_loader = SchemaLoader()
    _generator     = DataGenerator()
    _exposure      = ExposureTracker(_redis_client)
    _mutations     = MutationStore(_redis_client)
    _strategy_registry = StrategyRegistry.load_with_fallback()
    _policy_guard = PolicyGuard(_strategy_registry)
    _strategy_agent = RuleOnlyStrategyAgent(_policy_guard)
    if _strategy_registry.degraded:
        log.error("Strategy registry invalid; using built-in D0 fallback")
    log.info(
        "Deception engine started — schemas: %s registry=%s approved=%s",
        _schema_loader.get_schema_names(),
        _strategy_registry.registry_version,
        [item.strategy_id for item in _strategy_registry.approved()],
    )
    yield
    if _redis_client:
        _redis_client.close()


app = FastAPI(title="Deception Engine", lifespan=lifespan)
import sys
install_principals(app, sys.modules[__name__])

# ─── Routes ───────────────────────────────────────────────────────────────────

def _loaded_schema_names() -> list[str]:
    if _schema_loader is None:
        return []
    try:
        return _schema_loader.get_schema_names()
    except Exception:
        log.debug("schema-name lookup failed", exc_info=True)
        return []


def _redis_ready() -> bool:
    if _redis_client is None:
        return False
    try:
        return bool(_redis_client.ping())
    except Exception:
        return False


def _runtime_components_loaded() -> bool:
    """Return True when all in-process components required by /decide exist."""
    return (
        _schema_loader is not None
        and _generator is not None
        and _exposure is not None
        and _mutations is not None
        and _strategy_registry.resolve(
            _strategy_registry.default_strategy_id
        ).approval_status == "APPROVED"
        and _policy_guard.enforce_registered_choice(
            _strategy_registry.default_strategy_id
        ) == _strategy_registry.default_strategy_id
        and _strategy_agent.select_registered_rule(
            _strategy_registry.default_strategy_id
        ).strategy_id == _strategy_registry.default_strategy_id
    )


def _readiness_payload() -> dict:
    """Build a readiness payload without raising if one dependency is unhealthy."""
    schemas = _loaded_schema_names()
    redis_ok = _redis_ready()
    checks = {
        "app_started": True,
        "schemas_loaded": bool(schemas),
        "generator_loaded": _generator is not None,
        "exposure_tracker_loaded": _exposure is not None,
        "mutation_store_loaded": _mutations is not None,
        "strategy_registry_default_approved": (
            _strategy_registry.resolve(
                _strategy_registry.default_strategy_id
            ).approval_status == "APPROVED"
        ),
        "policy_guard_default_approved": (
            _policy_guard.enforce_registered_choice(
                _strategy_registry.default_strategy_id
            ) == _strategy_registry.default_strategy_id
        ),
        "rule_strategy_agent_default_approved": (
            _strategy_agent.select_registered_rule(
                _strategy_registry.default_strategy_id
            ).strategy_id == _strategy_registry.default_strategy_id
        ),
        "redis": redis_ok,
    }
    ready = all(checks.values())
    return {
        "status": "ready" if ready else "not_ready",
        "service": "deception-engine",
        "ready": ready,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": checks,
        "schema_count": len(schemas),
        "schemas": schemas,
        "strategy_registry_version": _strategy_registry.registry_version,
        "strategy_registry_degraded": _strategy_registry.degraded,
        "policy_guard_version": POLICY_VERSION,
        "rule_strategy_agent_version": RULE_POLICY_VERSION,
    }


def _byte_len(value: object) -> int:
    """Return UTF-8 byte length for request validation."""
    if value is None:
        return 0
    return len(str(value).encode("utf-8"))


def _normalise_request_protocol(value: object) -> str:
    """Normalise supported DB protocol names used by proxies."""
    protocol = str(value or "").strip().lower()
    if protocol in {"pg", "postgres", "postgresql"} or protocol.startswith("postgres"):
        return "postgres"
    if protocol == "mysql" or protocol.startswith("mysql"):
        return "mysql"
    return protocol


def _decision_request_field_names() -> set[str]:
    """Return DecisionRequest fields for dataclass and Pydantic v1/v2 models."""
    try:
        if dataclasses.is_dataclass(DecisionRequest):
            return {field.name for field in dataclasses.fields(DecisionRequest)}
    except Exception:
        pass

    fields = getattr(DecisionRequest, "model_fields", None)
    if isinstance(fields, dict):
        return set(fields.keys())

    fields = getattr(DecisionRequest, "__fields__", None)
    if isinstance(fields, dict):
        return set(fields.keys())

    return set()


def _prepare_decide_request_payload(payload: dict) -> dict:
    """Validate and normalise a raw /decide JSON body before Pydantic parsing.

    The proxy should send the full DecisionRequest shape, but direct tests and
    older proxy builds may omit non-critical fields such as fingerprint, phase,
    event_type, or username. Accept those with safe defaults so this endpoint
    can return our own 400/413 validation errors instead of FastAPI's generic
    422 response before the handler runs.
    """
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail={
                "status": "invalid_request",
                "errors": ["request body must be a JSON object"],
            },
        )

    data = dict(payload)
    errors: list[str] = []

    session_id = str(data.get("session_id", "") or "").strip()
    query_normalized = str(data.get("query_normalized", "") or "")
    query_raw = str(data.get("query_raw", "") or "")
    database = str(data.get("database", "") or "")
    protocol_raw = data.get("protocol", "")
    protocol = _normalise_request_protocol(protocol_raw)

    if not session_id:
        errors.append("missing required field: session_id")
    elif _byte_len(session_id) > DECIDE_MAX_SESSION_ID_BYTES:
        errors.append(f"session_id exceeds {DECIDE_MAX_SESSION_ID_BYTES} bytes")

    if not query_normalized.strip():
        errors.append("missing required field: query_normalized")
    elif _byte_len(query_normalized) > DECIDE_MAX_QUERY_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "status": "invalid_request",
                "error": f"query_normalized exceeds {DECIDE_MAX_QUERY_BYTES} bytes",
                "max_query_bytes": DECIDE_MAX_QUERY_BYTES,
            },
        )

    if query_raw and _byte_len(query_raw) > DECIDE_MAX_QUERY_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "status": "invalid_request",
                "error": f"query_raw exceeds {DECIDE_MAX_QUERY_BYTES} bytes",
                "max_query_bytes": DECIDE_MAX_QUERY_BYTES,
            },
        )

    if database and _byte_len(database) > DECIDE_MAX_DATABASE_BYTES:
        errors.append(f"database exceeds {DECIDE_MAX_DATABASE_BYTES} bytes")

    if not str(protocol_raw or "").strip():
        errors.append("missing required field: protocol")
    elif protocol not in {"mysql", "postgres"}:
        errors.append(f"unsupported protocol: {protocol_raw}")

    deception_level_raw = data.get("deception_level", None)
    deception_level = None
    if isinstance(deception_level_raw, bool) or deception_level_raw is None:
        errors.append("invalid deception_level")
    else:
        try:
            deception_level = int(deception_level_raw)
            if deception_level < DECIDE_MIN_DECEPTION_LEVEL or deception_level > DECIDE_MAX_DECEPTION_LEVEL:
                errors.append(
                    f"deception_level must be between {DECIDE_MIN_DECEPTION_LEVEL} and {DECIDE_MAX_DECEPTION_LEVEL}"
                )
        except (TypeError, ValueError):
            errors.append("invalid deception_level")

    risk_score_raw = data.get("risk_score", 0.0)
    risk_score = 0.0
    try:
        risk_score = float(risk_score_raw)
        if not math.isfinite(risk_score) or risk_score < DECIDE_MIN_RISK_SCORE or risk_score > DECIDE_MAX_RISK_SCORE:
            errors.append(
                f"risk_score must be between {DECIDE_MIN_RISK_SCORE:g} and {DECIDE_MAX_RISK_SCORE:g}"
            )
    except (TypeError, ValueError):
        errors.append("invalid risk_score")

    transaction_state = str(data.get("transaction_state") or "idle").strip().lower()
    if transaction_state not in {"idle", "in_transaction", "failed_transaction"}:
        errors.append("invalid transaction_state")

    if errors:
        log.warning(
            "Rejected /decide request: errors=%s session=%s protocol=%s query_preview=%s",
            errors,
            session_id[:16],
            protocol_raw,
            query_normalized[:120].replace("\n", " ").replace("\r", " "),
        )
        raise HTTPException(
            status_code=400,
            detail={
                "status": "invalid_request",
                "errors": errors,
            },
        )

    # Safe compatibility defaults for fields that the DecisionRequest model may
    # require but that are not security-critical for /decide behavior.
    data["session_id"] = session_id
    data["query_normalized"] = query_normalized
    data["query_raw"] = query_raw or query_normalized
    data["database"] = database
    data["protocol"] = protocol
    data["fingerprint"] = str(data.get("fingerprint") or query_normalized)
    data["event_type"] = str(data.get("event_type") or "query")
    data["phase"] = str(data.get("phase") or "")
    data["username"] = str(data.get("username") or data.get("db_user") or "unknown")
    data["table"] = str(data.get("table") or "")
    data["deception_level"] = deception_level
    data["risk_score"] = risk_score
    data["transaction_state"] = transaction_state

    # The /decide handler intentionally uses SimpleNamespace instead of
    # constructing DecisionRequest, because this project has used both dataclass
    # and stricter model variants over time. Keep safe extra fields such as
    # table/query_raw/client_ip available to downstream handlers.
    return data


def _normalise_rate_limit_identity(value: object, fallback: str = "unknown") -> str:
    """Return a bounded Redis-key-safe identity string for rate-limit keys."""
    text = str(value or fallback).strip() or fallback
    text = re.sub(r"[^A-Za-z0-9_.:@-]+", "_", text)
    return text[:160]


def _client_identity(request: Request, raw_body: dict) -> str:
    """Prefer proxy-provided client IP; fall back to HTTP peer/header."""
    body_client = raw_body.get("client_ip") or raw_body.get("source_ip") if isinstance(raw_body, dict) else None
    if body_client:
        return _normalise_rate_limit_identity(body_client)
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return _normalise_rate_limit_identity(forwarded.split(",")[0].strip())
    if request.client and request.client.host:
        return _normalise_rate_limit_identity(request.client.host)
    return "unknown"


def _rate_limit_counter(scope: str, identity: str, limit: int, window_seconds: int) -> tuple[bool, int, int]:
    """Increment a Redis counter and return (allowed, current_count, retry_after)."""
    if limit <= 0:
        return True, 0, 0
    if _redis_client is None:
        raise RuntimeError("Redis client not initialised")

    now = int(time.time())
    window_seconds = max(1, int(window_seconds))
    bucket = now // window_seconds
    retry_after = max(1, ((bucket + 1) * window_seconds) - now)
    key = f"rate:decide:{scope}:{identity}:{bucket}"

    pipe = _redis_client.pipeline()
    pipe.incr(key)
    pipe.expire(key, window_seconds + 5)
    result = pipe.execute()
    count = int(result[0])
    return count <= limit, count, retry_after


def _enforce_decide_rate_limit(request: Request, raw_body: dict, payload: dict) -> None:
    """Apply global, client, and session /decide rate limits.

    The limit is intentionally enforced after semantic validation, so malformed
    input still receives useful 400/413 errors while valid high-rate probes are
    throttled before expensive fake-data generation.
    """
    if not DECIDE_RATE_LIMIT_ENABLED:
        return

    try:
        window_seconds = max(1, DECIDE_RATE_LIMIT_WINDOW_SECONDS)
        checks: list[tuple[str, str, int]] = []

        if DECIDE_RATE_LIMIT_GLOBAL > 0:
            checks.append(("global", "all", DECIDE_RATE_LIMIT_GLOBAL))

        client_id = _client_identity(request, raw_body)
        if DECIDE_RATE_LIMIT_PER_CLIENT > 0 and client_id:
            checks.append(("client", client_id, DECIDE_RATE_LIMIT_PER_CLIENT))

        session_id = _normalise_rate_limit_identity(payload.get("session_id"), "missing-session")
        if DECIDE_RATE_LIMIT_PER_SESSION > 0 and session_id:
            checks.append(("session", session_id, DECIDE_RATE_LIMIT_PER_SESSION))

        for scope, identity, limit in checks:
            allowed, count, retry_after = _rate_limit_counter(scope, identity, limit, window_seconds)
            if not allowed:
                log.warning(
                    "Rate limited /decide: scope=%s identity=%s count=%d limit=%d window=%ds",
                    scope, identity, count, limit, window_seconds,
                )
                raise HTTPException(
                    status_code=429,
                    detail={
                        "status": "rate_limited",
                        "scope": scope,
                        "identity": identity,
                        "count": count,
                        "limit": limit,
                        "window_seconds": window_seconds,
                        "retry_after_seconds": retry_after,
                    },
                    headers={"Retry-After": str(retry_after)},
                )
    except HTTPException:
        raise
    except Exception as e:
        if DECIDE_RATE_LIMIT_FAIL_OPEN:
            log.warning("/decide rate limiter failed open: %s", e)
            return
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "service": "deception-engine",
                "reason": "rate limiter unavailable",
            },
        )


@app.get("/health")
@app.get("/healthz")
async def health():
    """Liveness endpoint: process is alive, regardless of dependency readiness."""
    return {
        "status": "ok",
        "service": "deception-engine",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@app.get("/ready")
@app.get("/readyz")
async def readyz():
    """Readiness endpoint: only 200 when /decide can safely serve requests."""
    payload = _readiness_payload()
    return JSONResponse(
        status_code=200 if payload["ready"] else 503,
        content=payload,
    )


@app.get("/strategies")
async def list_strategies() -> dict:
    """Return the versioned deterministic registry; this endpoint is read-only."""
    return _strategy_registry.to_dict()


@app.get("/strategies/{strategy_id}")
async def get_strategy(strategy_id: str) -> dict:
    """Return one mapped entry without activating or approving it."""
    strategy = _strategy_registry.get(strategy_id)
    if strategy is None:
        raise HTTPException(status_code=404, detail="strategy not found")
    return strategy.to_dict()


def _sync_strategy_runtime() -> None:
    global _policy_guard, _strategy_agent
    if _policy_guard.registry is not _strategy_registry:
        _policy_guard = PolicyGuard(_strategy_registry)
    if _strategy_agent.policy_guard is not _policy_guard:
        _strategy_agent = RuleOnlyStrategyAgent(_policy_guard)


@app.post("/strategy/next")
async def next_strategy(body: dict = Body(...)) -> dict:
    """Internal slow-path rule decision from structured evidence only."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request must be an object")
    if len(json.dumps(body, separators=(",", ":"))) > 131_072:
        raise HTTPException(status_code=413, detail="request too large")
    allowed = {"session_state", "behavior_state", "mitre_state", "operator_mode"}
    if set(body) - allowed:
        raise HTTPException(status_code=400, detail="unexpected request fields")
    states = tuple(body.get(name, {}) for name in (
        "session_state", "behavior_state", "mitre_state"
    ))
    if any(not isinstance(state, dict) for state in states):
        raise HTTPException(status_code=400, detail="state inputs must be objects")
    forbidden = {
        "query", "query_normalized", "fingerprint", "client_ip", "source_ip",
        "raw_sql", "prompt",
    }
    if any(key in forbidden for state in states for key in state):
        raise HTTPException(status_code=400, detail="raw or identifying input is forbidden")
    session_ids = {
        str(state.get("session_id") or "").strip()
        for state in states if state.get("session_id")
    }
    if not session_ids or len(session_ids) != 1:
        raise HTTPException(status_code=400, detail="one consistent session_id is required")
    _sync_strategy_runtime()
    decision, action_space = _strategy_agent.decide_with_action_space(
        states[0], states[1], states[2], body.get("operator_mode", "STATIC")
    )
    result = decision.to_dict()
    result.update({
        "allowed_actions": list(action_space.allowed),
        "rule_default_action": action_space.default,
    })
    return result

@app.post("/decide", response_model=None)
async def decide(request: Request, body: dict = Body(...)) -> JSONResponse:
    """
    Main decision endpoint. Called by the proxy shaper for every query.
    Returns a DecisionResponse as JSON.
    """
    if not _runtime_components_loaded():
        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "service": "deception-engine",
                "reason": "runtime components not initialised",
                "readiness": _readiness_payload(),
            },
        )

    payload = _prepare_decide_request_payload(body)
    _enforce_decide_rate_limit(request, body, payload)

    # Do not construct DecisionRequest here. In this codebase DecisionRequest has
    # existed as a dataclass in some builds and as a stricter validation model in
    # others. The endpoint has already validated and normalised the request, and
    # the downstream handlers only require attribute access. A SimpleNamespace
    # keeps /decide backward-compatible with older proxy payloads while avoiding
    # a second schema layer rejecting safe defaulted fields.
    req = SimpleNamespace(**payload)

    # Use query_normalized for all pattern matching — fingerprint is the FNV hash,
    # not human-readable text. query_normalized is the lowercased SQL template.
    fp = req.query_normalized.strip().lower()
    schema_name = _schema_loader.schema_for_database(req.database)

    # 1. System variable / banner queries — always fake regardless of level.
    # Use protocol-native column names for PostgreSQL so psql/ORM scanners see
    # plausible results instead of MySQL-style generic `value` columns.
    system_resp = _system_var_response(req, fp)
    if system_resp is not None:
        return system_resp

    # 2. Database/schema enumeration. MySQL scanners use SHOW DATABASES;
    # PostgreSQL scanners typically query pg_database. Return protocol-native
    # column names so client-side tooling looks plausible.
    if (
        "show databases" in fp
        or "show schemas" in fp
        or " from pg_database" in fp
        or " from pg_catalog.pg_database" in fp
        or " from information_schema.schemata" in fp
    ):
        databases = _visible_databases(req)
        if " from information_schema.schemata" in fp:
            return _json_response(DecisionResponse(
                mode="fake",
                databases=databases,
                rows=[{"schema_name": db} for db in databases],
                columns=["schema_name"],
                column_types=["text"],
                latency_ms=_latency(req.deception_level, base=30),
                profile="fake_schema",
                strategy_id="D1",
            ))
        if req.protocol.lower().startswith("postgres") or " from pg_database" in fp:
            database_rows = databases
            datname_match = re.search(r"\bdatname\s*=\s*'([^']+)'", fp, re.I)
            if datname_match:
                database_rows = [db for db in databases if db == datname_match.group(1)]
            return _json_response(DecisionResponse(
                mode="fake",
                databases=database_rows,
                rows=[{"datname": db} for db in database_rows],
                columns=["datname"],
                column_types=["text"],
                latency_ms=_latency(req.deception_level, base=30),
                profile="fake_schema",
                strategy_id="D1",
            ))
        return _json_response(DecisionResponse(
            mode="fake",
            databases=databases,
            rows=[{"Database": db} for db in databases],
            columns=["Database"],
            column_types=["text"],
            latency_ms=_latency(req.deception_level, base=30),
            profile="fake_schema",
            strategy_id="D1",
        ))

    # 3. PostgreSQL information_schema metadata.  Tables and columns are
    # rendered from the same YAML that drives fake rows, then filtered by the
    # bounded predicates used by common reconnaissance queries.
    if (
        " from information_schema.tables" in fp
        or " from information_schema.columns" in fp
    ):
        return await _handle_information_schema(req, schema_name, fp)

    # 4. Bounded protocol-native catalog reconnaissance.
    if req.protocol.lower().startswith("postgres") and _is_pg_catalog_query(fp):
        return await _handle_postgres_catalog(req, schema_name, fp)

    mysql_metadata_table = _extract_mysql_metadata_table(fp)
    if mysql_metadata_table:
        return await _handle_mysql_columns(req, schema_name, mysql_metadata_table)

    # 5. Table enumeration — progressive exposure.
    if (
        "show tables" in fp
        or "show full tables" in fp
    ):
        return await _handle_show_tables(req, schema_name)

    table = req.table or _extract_table(fp)

    if table and _schema_loader.get_table(schema_name, table):
        invalid = _validate_managed_sql(req, fp, table, schema_name)
        if invalid is not None:
            return invalid

    # 6. COUNT(*) query
    if _is_count_query(fp):
        return await _handle_count(req, fp, schema_name)

    # 7. Managed mutations must be classified before generic table reads.
    # The handlers already existed, but the earlier branch order made them
    # unreachable for known fake tables and returned SELECT-shaped rows instead.
    if _is_mutation(fp):
        return await _handle_mutation(req, fp, table, schema_name)

    # 8. SELECT from a known fake table
    if table and _schema_loader.get_table(schema_name, table):
        return await _handle_select(req, table, schema_name)

    # 9. SELECT from unknown table — passthrough to real backend
    return _json_response(DecisionResponse(
        mode="passthrough",
        explanation="Table not in fake schema — forwarding to backend",
    ))


# ─── Handlers ─────────────────────────────────────────────────────────────────

_INFORMATION_SCHEMA_TABLE_COLUMNS = [
    "table_catalog", "table_schema", "table_name", "table_type",
]
_INFORMATION_SCHEMA_COLUMN_COLUMNS = [
    "table_catalog", "table_schema", "table_name", "column_name",
    "ordinal_position", "column_default", "is_nullable", "data_type",
    "numeric_precision", "numeric_scale",
]
_SUPPORTED_METADATA_FILTERS = {"table_schema", "table_name", "column_name"}


def _is_pg_catalog_query(query: str) -> bool:
    return any(
        marker in query
        for marker in (
            " from pg_catalog.pg_tables", " from pg_tables",
            " from pg_catalog.pg_class", " from pg_catalog.pg_attribute",
            " from pg_catalog.pg_constraint", " from pg_catalog.pg_index",
            " from pg_catalog.pg_inherits", " from pg_catalog.pg_trigger",
            " from pg_catalog.pg_policy", " from pg_catalog.pg_statistic_ext",
            " from pg_catalog.pg_publication",
        )
    )


def _stable_relation_oid(schema_name: str, table_name: str) -> int:
    tables = list(_schema_loader.get_all_tables(schema_name))
    return 80000 + tables.index(table_name) if table_name in tables else 0


def _table_for_relation_oid(schema_name: str, oid: int) -> str:
    for table_name in _schema_loader.get_all_tables(schema_name):
        if _stable_relation_oid(schema_name, table_name) == oid:
            return table_name
    return ""


def _pg_catalog_requested_table(query: str) -> str:
    patterns = (
        r"\bc\.relname\s*=\s*'([a-z_][a-z0-9_$]*)'",
        r"\btablename\s*=\s*'([a-z_][a-z0-9_$]*)'",
        r"\^\((?:public\\\.)?([a-z_][a-z0-9_$]*)\)\$",
    )
    for pattern in patterns:
        match = re.search(pattern, query, re.I)
        if match:
            return match.group(1).lower()
    return ""


async def _handle_postgres_catalog(
    req: DecisionRequest, schema_name: str, query: str
) -> JSONResponse:
    r"""Serve only the catalog shapes used by pg_tables and psql \dt/\d."""
    depth = _exposure.get_depth(req.session_id)
    visible = _schema_loader.get_tables_at_depth(schema_name, depth)

    if "pg_tables" in query:
        rows = [
            {
                "schemaname": DEFAULT_SCHEMA,
                "tablename": table,
                "tableowner": req.username or "postgres",
                "tablespace": None,
                "hasindexes": False,
                "hasrules": False,
                "hastriggers": False,
                "rowsecurity": False,
            }
            for table in visible
        ]
        available = list(rows[0]) if rows else ["schemaname", "tablename"]
        columns = _simple_projection(query, available, default=available)
        rows = [{column: row.get(column) for column in columns} for row in rows]
        return _json_response(DecisionResponse(
            mode="fake", rows=rows, columns=columns,
            column_types=["boolean" if column.startswith("has") or column == "rowsecurity" else "text" for column in columns],
            profile="fake_schema", strategy_id="D1",
            explanation=f"Bounded pg_tables catalog at exposure depth {depth}",
        ))

    if any(marker in query for marker in (
        "pg_catalog.pg_inherits", "pg_catalog.pg_policy",
        "pg_catalog.pg_statistic_ext", "pg_catalog.pg_publication",
        "pg_catalog.pg_constraint", "pg_catalog.pg_index",
        "pg_catalog.pg_trigger",
    )):
        return _json_response(DecisionResponse(
            mode="fake", rows=[], columns=["Name"], column_types=["text"],
            profile="fake_schema", strategy_id="D1",
            explanation="No optional relation objects declared by deceptive schema",
        ))

    if "pg_catalog.pg_class" in query:
        if "c.relchecks" in query:
            oid_match = re.search(r"\bc\.oid\s*=\s*'?([0-9]+)'?", query, re.I)
            table = _table_for_relation_oid(schema_name, int(oid_match.group(1))) if oid_match else ""
            rows = []
            if table in visible:
                rows = [{
                    "relchecks": 0,
                    "relkind": "r",
                    "relhasindex": False,
                    "relhasrules": False,
                    "relhastriggers": False,
                    "relrowsecurity": False,
                    "relforcerowsecurity": False,
                    "relhasoids": False,
                    "relispartition": False,
                    "partition_parent": "",
                    "reltablespace": 0,
                    "reloftype": "",
                    "relpersistence": "p",
                    "relreplident": "d",
                    "amname": "heap",
                }]
            columns = [
                "relchecks", "relkind", "relhasindex", "relhasrules",
                "relhastriggers", "relrowsecurity", "relforcerowsecurity",
                "relhasoids", "relispartition", "partition_parent",
                "reltablespace", "reloftype", "relpersistence",
                "relreplident", "amname",
            ]
            types = [
                "integer", "text", "boolean", "boolean", "boolean",
                "boolean", "boolean", "boolean", "boolean", "text",
                "integer", "text", "text", "text", "text",
            ]
            return _json_response(DecisionResponse(
                mode="fake", rows=rows, columns=columns, column_types=types,
                profile="fake_schema", strategy_id="D1",
                explanation="Bounded psql relation detail catalog",
            ))
        requested = _pg_catalog_requested_table(query)
        selected = [requested] if requested in visible else ([] if requested else visible)
        if 'as "schema"' in query or " as schema" in query:
            columns = ["Schema", "Name", "Type", "Owner"]
            rows = [
                {"Schema": DEFAULT_SCHEMA, "Name": table, "Type": "table", "Owner": req.username or "postgres"}
                for table in selected
            ]
            types = ["text"] * 4
        else:
            columns = ["oid", "nspname", "relname"]
            rows = [
                {"oid": _stable_relation_oid(schema_name, table), "nspname": DEFAULT_SCHEMA, "relname": table}
                for table in selected
            ]
            types = ["integer", "text", "text"]
        return _json_response(DecisionResponse(
            mode="fake", rows=rows, columns=columns, column_types=types,
            profile="fake_schema", strategy_id="D1",
            explanation=f"Bounded pg_class catalog at exposure depth {depth}",
        ))

    if "pg_catalog.pg_attribute" in query:
        oid_match = re.search(r"attrelid\s*=\s*'?([0-9]+)'?", query, re.I)
        table = _table_for_relation_oid(schema_name, int(oid_match.group(1))) if oid_match else ""
        if table not in visible:
            table = ""
        rows = []
        for column in _schema_loader.get_columns(schema_name, table) if table else []:
            rows.append({
                "Column": column["name"],
                "Type": _column_sql_type(column),
                "Collation": None,
                "NotNull": not column.get("nullable", False),
                "Default": None,
                "Identity": "",
                "Generated": "",
            })
        columns = [
            "Column", "Type", "Default", "NotNull", "Collation",
            "Identity", "Generated",
        ]
        return _json_response(DecisionResponse(
            mode="fake", rows=rows, columns=columns,
            column_types=["text", "text", "text", "boolean", "text", "text", "text"],
            profile="fake_schema",
            strategy_id="D1", explanation="Bounded pg_attribute relation description",
        ))

    # psql asks optional follow-up catalogs for indexes, constraints, policies,
    # inheritance and triggers.  The current YAML declares none, so an empty
    # typed result is the truthful bounded answer.
    return _json_response(DecisionResponse(
        mode="fake", rows=[], columns=["Name"], column_types=["text"],
        profile="fake_schema", strategy_id="D1",
        explanation="No optional catalog objects declared by deceptive schema",
    ))


def _extract_mysql_metadata_table(query: str) -> str:
    match = re.match(
        r"^(?:describe|desc)\s+([a-z_][a-z0-9_$]*(?:\.[a-z_][a-z0-9_$]*)?)$",
        query, re.I,
    )
    if not match:
        match = re.match(
            r"^show\s+(?:columns|fields)\s+from\s+([a-z_][a-z0-9_$]*(?:\.[a-z_][a-z0-9_$]*)?)(?:\s+from\s+[a-z_][a-z0-9_$]*)?$",
            query, re.I,
        )
    return match.group(1).split(".")[-1].lower() if match else ""


async def _handle_mysql_columns(
    req: DecisionRequest, schema_name: str, table: str
) -> JSONResponse:
    table_def = _schema_loader.get_table(schema_name, table)
    if not table_def:
        return _json_response(DecisionResponse(
            mode="passthrough",
            explanation="Metadata target is not in fake schema — forwarding to backend",
        ))
    denied = _table_access_error(req, schema_name, table, table_def)
    if denied is not None:
        return denied
    columns = ["Field", "Type", "Null", "Key", "Default", "Extra"]
    return _json_response(DecisionResponse(
        mode="fake", rows=_schema_loader.get_mysql_columns(schema_name, table),
        columns=columns, column_types=["text"] * len(columns),
        profile="fake_schema", strategy_id="D1",
        explanation=f"YAML-backed MySQL metadata for {table}",
    ))


async def _handle_information_schema(
    req: DecisionRequest, schema_name: str, fp: str
) -> JSONResponse:
    """Serve a bounded, query-aware PostgreSQL metadata catalog."""
    depth = _exposure.get_depth(req.session_id)
    is_columns = " from information_schema.columns" in fp
    if is_columns:
        available = _INFORMATION_SCHEMA_COLUMN_COLUMNS
        rows = _schema_loader.get_metadata_columns(
            schema_name, depth, table_catalog=req.database or DEFAULT_DATABASE
        )
    else:
        available = _INFORMATION_SCHEMA_TABLE_COLUMNS
        rows = _schema_loader.get_metadata_tables(
            schema_name, depth, table_catalog=req.database or DEFAULT_DATABASE
        )

    invalid = _validate_metadata_sql(req, fp, available)
    if invalid is not None:
        return invalid

    rows = _filter_metadata_rows(rows, fp)
    columns = _metadata_projection(fp, available)
    projected = [{column: row.get(column) for column in columns} for row in rows]
    visible_tables = list(dict.fromkeys(row["table_name"] for row in rows))
    trap_tables = set(_schema_loader.get_trap_tables(schema_name))

    return _json_response(DecisionResponse(
        mode="fake",
        tables=visible_tables if not is_columns else [],
        rows=projected,
        columns=columns,
        column_types=[_metadata_result_type(column) for column in columns],
        latency_ms=_latency(req.deception_level, base=35),
        profile="fake_schema",
        is_trap=bool(trap_tables.intersection(visible_tables)),
        explanation=(
            f"Filtered information_schema.{'columns' if is_columns else 'tables'} "
            f"depth={depth}, {len(projected)} rows"
        ),
        strategy_id="D1",
    ))


def _metadata_projection(query: str, available: list[str]) -> list[str]:
    """Extract only simple supported SELECT-list identifiers."""
    match = re.search(r"\bselect\s+(.*?)\s+from\s+information_schema\.", query, re.I)
    if not match:
        return list(available)
    select_list = re.sub(r"^distinct\s+", "", match.group(1).strip(), flags=re.I)
    if select_list == "*":
        return list(available)

    projected: list[str] = []
    for expression in select_list.split(",")[:len(available)]:
        expression = expression.strip()
        expression = re.sub(r"\s+as\s+\w+$", "", expression, flags=re.I)
        identifier = expression.split(".")[-1].strip(' "')
        if identifier in available and identifier not in projected:
            projected.append(identifier)
    return projected or list(available)


def _simple_projection(
    query: str, available: list[str], *, default: list[str]
) -> list[str]:
    match = re.search(r"\bselect\s+(.*?)\s+from\s+", query, re.I)
    if not match:
        return list(default)
    selection = re.sub(r"^distinct\s+", "", match.group(1).strip(), flags=re.I)
    if selection == "*":
        return list(available)
    columns: list[str] = []
    for expression in selection.split(","):
        base = re.sub(r"\s+as\s+.+$", "", expression.strip(), flags=re.I)
        name = base.split(".")[-1].strip(' `"')
        if name in available and name not in columns:
            columns.append(name)
    return columns or list(default)


def _filter_metadata_rows(rows: list[dict], query: str) -> list[dict]:
    """Apply literal =/LIKE/ILIKE predicates for three metadata fields."""
    where = query.split(" where ", 1)[1] if " where " in query else ""
    predicate_pattern = re.compile(
        r"(?:(?:\b\w+)\.)?(table_schema|table_name|column_name)\s*"
        r"(=|like|ilike)\s*'((?:''|[^'])*)'",
        re.I,
    )
    predicates = [
        (match.group(1).lower(), match.group(2).lower(), match.group(3).replace("''", "'"))
        for match in predicate_pattern.finditer(where)
        if match.group(1).lower() in _SUPPORTED_METADATA_FILTERS
    ]
    if not predicates:
        filtered = rows
    else:
        def matches(row: dict) -> bool:
            for field, operator, expected in predicates:
                actual = str(row.get(field, ""))
                if operator == "=" and actual != expected:
                    return False
                if operator in {"like", "ilike"}:
                    pattern = "".join(
                        ".*" if char == "%" else "." if char == "_" else re.escape(char)
                        for char in expected
                    )
                    flags = re.I if operator == "ilike" else 0
                    if re.fullmatch(pattern, actual, flags=flags) is None:
                        return False
            return True

        filtered = [row for row in rows if matches(row)]

    limit_match = re.search(r"\blimit\s+(\d+)\b", query, re.I)
    if limit_match:
        filtered = filtered[:min(int(limit_match.group(1)), 500)]
    return filtered


def _metadata_result_type(column: str) -> str:
    if column in {"ordinal_position", "numeric_precision", "numeric_scale"}:
        return "integer"
    return "text"


def _column_sql_type(column: dict) -> str:
    from schema_loader import SQL_TYPE_BY_GENERATOR_TYPE
    return column.get(
        "sql_type",
        SQL_TYPE_BY_GENERATOR_TYPE.get(column.get("type", "sentence"), "character varying"),
    )


def _syntax_error(req: DecisionRequest, message: str) -> JSONResponse:
    protocol = str(getattr(req, "protocol", "mysql") or "mysql").lower()
    if protocol.startswith("postgres"):
        return _json_response(DecisionResponse(
            mode="block", error_msg=message, sqlstate="42601",
            explanation="Unsupported or malformed bounded deceptive SQL",
        ))
    return _json_response(DecisionResponse(
        mode="block", error_msg=message, error_code=1064, sqlstate="42000",
        explanation="Unsupported or malformed bounded deceptive SQL",
    ))


def _column_error(req: DecisionRequest, column: str) -> JSONResponse:
    protocol = str(getattr(req, "protocol", "mysql") or "mysql").lower()
    if protocol.startswith("postgres"):
        return _json_response(DecisionResponse(
            mode="block", error_msg=f'column "{column}" does not exist', sqlstate="42703",
        ))
    return _json_response(DecisionResponse(
        mode="block", error_msg=f"Unknown column '{column}' in 'field list'",
        error_code=1054, sqlstate="42S22",
    ))


def _validate_metadata_sql(
    req: DecisionRequest, query: str, available: list[str]
) -> JSONResponse | None:
    if re.search(r"\bin\s*\(", query, re.I):
        return _syntax_error(req, "unsupported metadata predicate")
    if re.search(r"\border\s+by\b", query, re.I):
        return _syntax_error(req, "unsupported metadata ORDER BY clause")
    if re.search(r"\blimit\b(?!\s+\d+\b)", query, re.I):
        return _syntax_error(req, "invalid LIMIT clause")
    where = query.split(" where ", 1)[1] if " where " in query else ""
    if where:
        where = re.split(r"\s+limit\s+", where, maxsplit=1, flags=re.I)[0]
        consumed = re.sub(
            r"(?:(?:\b\w+)\.)?(?:table_schema|table_name|column_name)\s*(?:=|like|ilike)\s*'(?:''|[^'])*'",
            "", where, flags=re.I,
        )
        consumed = re.sub(r"\s+and\s+", "", consumed, flags=re.I).strip(" ();")
        if consumed:
            return _syntax_error(req, "unsupported metadata predicate")
    projected = _metadata_projection(query, available)
    select_match = re.search(r"\bselect\s+(.*?)\s+from\s+information_schema\.", query, re.I)
    if select_match and select_match.group(1).strip() != "*":
        raw = re.sub(r"^distinct\s+", "", select_match.group(1).strip(), flags=re.I)
        identifiers = [
            re.sub(r"\s+as\s+\w+$", "", part.strip(), flags=re.I).split(".")[-1].strip(' "')
            for part in raw.split(",")
        ]
        unknown = next((name for name in identifiers if name not in available), "")
        if unknown:
            return _column_error(req, unknown)
        if not projected:
            return _syntax_error(req, "invalid metadata projection")
    return None


def _validate_managed_sql(
    req: DecisionRequest, query: str, table: str, schema_name: str
) -> JSONResponse | None:
    """Validate the intentionally small managed-table SQL grammar."""
    if _is_mutation(query):
        if query.startswith("update "):
            if _parse_id_predicate(query) is None:
                return _syntax_error(req, "UPDATE requires WHERE id = positive integer")
            assignments = _parse_update_assignments(
                query, {column["name"] for column in _schema_loader.get_columns(schema_name, table)}
            )
            if not assignments:
                return _syntax_error(req, "unsupported UPDATE assignment")
        elif query.startswith("delete ") and _parse_id_predicate(query) is None:
            return _syntax_error(req, "DELETE requires WHERE id = positive integer")
        elif query.startswith("insert ") and not re.fullmatch(
            r"insert\s+into\s+[a-z_][a-z0-9_$]*(?:\.[a-z_][a-z0-9_$]*)?\s*"
            r"\([a-z_][a-z0-9_$]*(?:\s*,\s*[a-z_][a-z0-9_$]*)*\)\s*"
            r"values\s*\(.+\)", query, re.I,
        ):
            return _syntax_error(req, "unsupported INSERT syntax")
        return None

    if not query.startswith("select "):
        return _syntax_error(req, "unsupported statement for deceptive table")
    if re.search(r"\border\s+by\b", query, re.I):
        return _syntax_error(req, "unsupported ORDER BY clause")
    if re.search(r"\bwhere\s*$", query, re.I):
        return _syntax_error(req, "malformed WHERE clause")
    if re.search(r"\blimit\b(?!\s+\d+\b)", query, re.I):
        return _syntax_error(req, "invalid LIMIT clause")
    if re.search(r"\boffset\b(?!\s+\d+\b)", query, re.I):
        return _syntax_error(req, "invalid OFFSET clause")
    if " where " in query and _parse_id_predicate(query) is None:
        return _syntax_error(req, "unsupported WHERE predicate")
    columns = [column["name"] for column in _schema_loader.get_columns(schema_name, table)]
    match = re.search(r"\bselect\s+(.*?)\s+from\s+", query, re.I)
    if not match:
        return _syntax_error(req, "malformed SELECT")
    projection = match.group(1).strip()
    if projection.lower() == "count(*)":
        return None
    if projection != "*" and not projection.endswith(".*"):
        for expression in projection.split(","):
            expression = re.sub(r"\s+as\s+[a-z_][a-z0-9_]*$", "", expression.strip(), flags=re.I)
            identifier = expression.split(".")[-1].strip(' `"')
            if not re.fullmatch(r"[a-z_][a-z0-9_$]*", identifier, re.I):
                return _syntax_error(req, "unsupported SELECT projection")
            if identifier not in columns:
                return _column_error(req, identifier)
    return None

async def _handle_show_tables(
    req: DecisionRequest, schema_name: str
) -> JSONResponse:
    depth = _exposure.get_depth(req.session_id)
    visible = _schema_loader.get_tables_at_depth(schema_name, depth)
    # Check if any trap tables are visible (depth 3)
    trap_tables = _schema_loader.get_trap_tables(schema_name)
    is_trap = any(t in visible for t in trap_tables)
    if req.protocol.lower().startswith("postgres"):
        rows = [{"schemaname": "public", "tablename": t} for t in visible]
        columns = ["schemaname", "tablename"]
    else:
        column = f"Tables_in_{req.database or DEFAULT_DATABASE}"
        rows = [{column: t} for t in visible]
        columns = [column]

    return _json_response(DecisionResponse(
        mode="fake",
        tables=visible,
        rows=rows,
        columns=columns,
        column_types=["text"] * len(columns),
        latency_ms=_latency(req.deception_level, base=35),
        profile="fake_schema",
        is_trap=is_trap,
        explanation=f"Progressive exposure depth={depth}, {len(visible)} tables visible",
        strategy_id="D1",
    ))


async def _handle_count(
    req: DecisionRequest, fp: str, schema_name: str
) -> JSONResponse:
    table = _extract_table(fp) or req.table
    if not table:
        return _json_response(DecisionResponse(mode="passthrough"))

    table_def = _schema_loader.get_table(schema_name, table)
    if not table_def:
        return _json_response(DecisionResponse(mode="passthrough"))

    denied = _table_access_error(req, schema_name, table, table_def)
    if denied is not None:
        return denied

    # Advance depth only after the currently exposed object is authorized.
    table_depth = table_def.get("exposure_depth", 1)
    _exposure.record_table_access(req.session_id, table, table_depth)

    base_count = _generator.generate_count(
        table_def.get("row_count", 100), (principal_seed.get() or req.session_id), table
    )
    delta = _mutations.get_count_delta(req.session_id, table)
    count = max(0, base_count + delta)

    is_trap = table_def.get("is_trap", False)
    count_column = "count" if req.protocol.lower().startswith("postgres") else "COUNT(*)"
    return _json_response(DecisionResponse(
        mode="fake",
        count=count,
        rows=[{count_column: count}],
        columns=[count_column],
        column_types=["bigint"],
        latency_ms=_latency(req.deception_level, base=20),
        profile="fake_table_data",
        is_trap=is_trap,
        explanation=f"COUNT for {table}: {count} rows (base={base_count} delta={delta})",
        strategy_id=_strategy_id_for_table(schema_name, table),
    ))


async def _handle_select(
    req: DecisionRequest, table: str, schema_name: str
) -> JSONResponse:
    table_def = _schema_loader.get_table(schema_name, table)
    if not table_def:
        return _json_response(DecisionResponse(mode="passthrough"))

    denied = _table_access_error(req, schema_name, table, table_def)
    if denied is not None:
        return denied

    # Advance exploration depth only after authorization.
    table_depth = table_def.get("exposure_depth", 1)
    _exposure.record_table_access(req.session_id, table, table_depth)

    columns_def = _schema_loader.get_columns(schema_name, table)
    # Use the same deterministic effective count as COUNT(*) so pagination
    # probes cannot easily detect a mismatch between count and rows.
    base_count = _generator.generate_count(
        table_def.get("row_count", 100), (principal_seed.get() or req.session_id), table
    )
    limit, offset = _parse_limit_offset(req.query_normalized)
    row_id = _parse_id_predicate(req.query_normalized)
    if row_id is not None:
        offset = max(0, row_id - 1)
        limit = 1

    # Cap rows — never return more than 100 regardless of LIMIT
    effective_limit = min(limit, 100)

    if schema_name == "hr" and table in {"employees", "departments"}:
        schema_tables = _schema_loader.get_all_tables(schema_name)
        employee_def = schema_tables.get("employees", {})
        employee_count = _generator.generate_count(
            employee_def.get("row_count", 0), (principal_seed.get() or req.session_id), "employees"
        )
        available_limit = min(effective_limit, max(0, base_count - offset))
        rows = _generator.generate_organization_rows(
            schema_name=schema_name,
            table_name=table,
            schema_tables=schema_tables,
            employee_count=employee_count,
            session_id=(principal_seed.get() or req.session_id),
            limit=available_limit,
            offset=offset,
        )
    else:
        rows = _generator.generate_rows(
            columns=columns_def,
            row_count=base_count,
            session_id=(principal_seed.get() or req.session_id),
            table_name=table,
            limit=effective_limit,
            offset=offset,
        )

    # Merge session-local inserts, then apply bounded UPDATE/DELETE overlays.
    inserted = _mutations.get_inserted_rows(req.session_id, table)
    if row_id is not None:
        inserted_matches = [row for row in inserted if row.get("id") == row_id]
        rows = inserted_matches + [row for row in rows if row.get("id") == row_id]
    elif inserted and offset == 0:
        rows = inserted[:effective_limit] + rows[:max(0, effective_limit - len(inserted))]
    rows = _mutations.apply_rows(req.session_id, table, rows)

    all_col_names = [c["name"] for c in columns_def]
    col_names = _parse_select_projection(req.query_normalized, all_col_names)
    rows = [{column: row.get(column) for column in col_names} for row in rows]
    is_trap = table_def.get("is_trap", False)

    if is_trap:
        log.warning(
            "TRAP TABLE ACCESSED: session=%s table=%s depth=%d",
            _short_id(req.session_id), table, table_depth,
        )

    return _json_response(DecisionResponse(
        mode="fake",
        rows=rows,
        columns=col_names,
        column_types=[
            _column_sql_type(next(column for column in columns_def if column["name"] == name))
            for name in col_names
        ],
        latency_ms=_latency(req.deception_level, base=45),
        profile="high_value_target" if is_trap else "fake_table_data",
        is_trap=is_trap,
        explanation=f"Fake rows for {table}: {len(rows)} rows returned",
        strategy_id=_strategy_id_for_table(schema_name, table),
    ))


async def _handle_mutation(
    req: DecisionRequest, fp: str, table: str, schema_name: str
) -> JSONResponse:
    """
    Record INSERT/UPDATE/DELETE against managed fake tables and return a fake
    success response. Unknown tables are passed through: recording mutation
    state for an empty/unknown table creates later consistency leaks such as
    `{}` rows appearing in SELECT results.
    """
    table_def = _schema_loader.get_table(schema_name, table) if table else None
    if not table or not table_def:
        return _json_response(DecisionResponse(
            mode="passthrough",
            explanation="Mutation target is not in fake schema — forwarding to backend",
        ))

    denied = _table_access_error(req, schema_name, table, table_def)
    if denied is not None:
        return denied

    transaction_active = getattr(req, "transaction_state", "idle") == "in_transaction"
    affected = 0
    if fp.startswith("insert"):
        row = _fake_insert_row(req, schema_name, table)
        if row:
            _mutations.record_insert(
                req.session_id, table, row,
                transaction_active=transaction_active,
            )
            affected = 1
    elif fp.startswith("update"):
        row_id = _parse_id_predicate(fp)
        assignments = _parse_update_assignments(
            fp, {column["name"] for column in _schema_loader.get_columns(schema_name, table)}
        )
        if row_id is not None and assignments and _row_id_exists(req, schema_name, table, row_id):
            _mutations.record_update(
                req.session_id, table, "", "", row_id=row_id,
                assignments=assignments, transaction_active=transaction_active,
            )
            affected = 1
    elif fp.startswith("delete"):
        row_id = _parse_id_predicate(fp)
        if row_id is None:
            # Preserve the existing mutation-audit hook for placeholder or
            # unsupported predicates without pretending a row was deleted.
            _mutations.record_delete(
                req.session_id, table, "", row_id=None,
                transaction_active=transaction_active,
            )
        elif _row_id_exists(req, schema_name, table, row_id):
            _mutations.record_delete(
                req.session_id, table, "", row_id=row_id,
                transaction_active=transaction_active,
            )
            affected = 1

    return _json_response(DecisionResponse(
        mode="fake",
        rows=[],
        affected_rows=affected,
        latency_ms=_latency(req.deception_level, base=30),
        profile="fake_table_data",
        explanation=f"Mutation recorded: {fp[:30]} — {affected} rows affected",
        strategy_id="D6",
    ))


# ─── Session lifecycle ────────────────────────────────────────────────────────

@app.post("/session/start")
async def session_start(body: dict) -> dict:
    """Called when a new session is established."""
    session_id = body.get("session_id", "")
    if session_id:
        _exposure.initialise_session(session_id)
    return {"status": "ok"}


@app.post("/session/end")
async def session_end(body: dict) -> dict:
    """Called when a session closes — cleans up Redis state."""
    session_id = body.get("session_id", "")
    if session_id:
        _exposure.cleanup_session(session_id)
        _mutations.cleanup_session(session_id)
        _generator.cleanup_session(session_id)
    return {"status": "ok"}


@app.post("/transaction/{action}")
async def transaction_action(action: str, body: dict) -> dict:
    """Finalize one session-local deceptive mutation transaction."""
    action = str(action or "").strip().lower()
    session_id = str(body.get("session_id") or "").strip() if isinstance(body, dict) else ""
    if action not in {"commit", "rollback"}:
        raise HTTPException(status_code=400, detail="unsupported transaction action")
    if not session_id or _byte_len(session_id) > DECIDE_MAX_SESSION_ID_BYTES:
        raise HTTPException(status_code=400, detail="invalid session_id")
    _mutations.finalize_transaction(session_id, action)
    return {"status": "ok", "action": action, "session_id": session_id}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _short_id(value: str) -> str:
    return value[:8] if len(value) > 8 else value


def _system_var_response(req: DecisionRequest, fp: str) -> JSONResponse | None:
    protocol = (req.protocol or "mysql").strip().lower()
    if protocol.startswith("postgres") and fp in POSTGRES_SYSTEM_VAR_MAP:
        column, configured_value = POSTGRES_SYSTEM_VAR_MAP[fp]
        if configured_value is not None:
            value = configured_value
        elif column in ("current_database",):
            value = req.database or "postgres"
        elif column in ("current_user", "session_user"):
            value = req.username or "postgres"
        else:
            value = ""
        return _json_response(DecisionResponse(
            mode="fake",
            rows=[{column: value}],
            columns=[column],
            column_types=["integer" if column.endswith("port") else "text"],
            latency_ms=_latency(req.deception_level, base=25),
            profile="fake_system_info",
            explanation=f"PostgreSQL banner hardening: {fp} → {column}='{value}'",
        ))

    if fp in {"select database()", "select database"}:
        value = req.database or DEFAULT_DATABASE
        return _json_response(DecisionResponse(
            mode="fake", rows=[{"database()": value}], columns=["database()"],
            column_types=["text"], latency_ms=_latency(req.deception_level, base=25),
            profile="fake_system_info", explanation="Canonical connected database identity",
        ))

    if fp in SYSTEM_VAR_MAP:
        val = SYSTEM_VAR_MAP[fp]
        return _json_response(DecisionResponse(
            mode="fake",
            rows=[{"value": val}],
            columns=["value"],
            column_types=["text"],
            latency_ms=_latency(req.deception_level, base=25),
            profile="fake_system_info",
            explanation=f"Banner hardening: {fp} → '{val}'",
        ))
    return None


def _visible_databases(req: DecisionRequest) -> list[str]:
    connected = str(getattr(req, "database", "") or DEFAULT_DATABASE)
    return list(dict.fromkeys([*FAKE_DATABASES, connected]))


def _strategy_id_for_table(schema_name: str, table_name: str) -> str:
    """Map only existing approved assets; unknown assets stay on D0."""
    return _strategy_registry.strategy_for_asset(
        schema_name, table_name
    ).strategy_id


def _table_access_error(
    req: DecisionRequest, schema_name: str, table_name: str, table_def: dict
) -> JSONResponse | None:
    """Fail closed when a known deceptive object has not been exposed.

    Metadata visibility and direct access now use the same exposure authority.
    The registry check prevents an unapproved asset mapping from becoming an
    attacker-facing path even if a malformed schema definition gives it a low
    exposure depth.  Crucially, this function never records access, so a guessed
    hidden name cannot advance the session.
    """
    raw_depth = _exposure.get_depth(req.session_id)
    current_depth = raw_depth if isinstance(raw_depth, int) else 1
    required_depth = max(1, int(table_def.get("exposure_depth", 1)))
    strategy = _strategy_registry.strategy_for_asset(schema_name, table_name)
    authorized = (
        required_depth <= current_depth
        and strategy.approval_status == "APPROVED"
    )
    if authorized:
        return None
    return _relation_error(
        req,
        table_name,
        explanation=(
            f"Managed object unavailable at exposure depth {current_depth}; "
            f"required={required_depth} strategy={strategy.strategy_id}"
        ),
    )


def _relation_error(
    req: DecisionRequest, table_name: str, *, explanation: str = ""
) -> JSONResponse:
    protocol = str(getattr(req, "protocol", "mysql") or "mysql").lower()
    if protocol.startswith("postgres"):
        return _json_response(DecisionResponse(
            mode="block",
            error_msg=f'relation "{table_name}" does not exist',
            error_code=0,
            sqlstate="42P01",
            explanation=explanation,
        ))
    database = str(getattr(req, "database", "") or "testdb")
    return _json_response(DecisionResponse(
        mode="block",
        error_msg=f"Table '{database}.{table_name}' doesn't exist",
        error_code=1146,
        sqlstate="42S02",
        explanation=explanation,
    ))


def _json_response(resp: DecisionResponse) -> JSONResponse:
    import dataclasses
    _sync_strategy_runtime()
    resp.strategy_id = _strategy_agent.select_registered_rule(
        resp.strategy_id
    ).strategy_id
    resp.strategy_registry_version = _strategy_registry.registry_version
    return JSONResponse(content=dataclasses.asdict(resp))


def _latency(deception_level: int, base: int = 30) -> int:
    """Return latency_ms scaled by deception_level with jitter."""
    multiplier = {1: 0.5, 2: 1.0, 3: 1.5, 4: 2.0}.get(deception_level, 1.0)
    jitter = random.randint(-10, 10)
    return max(5, int(base * multiplier) + jitter)


def _is_count_query(fp: str) -> bool:
    return "count(*)" in fp or "count(?)" in fp


def _is_mutation(fp: str) -> bool:
    return fp.startswith(("insert ", "update ", "delete "))


def _fake_insert_row(req: DecisionRequest, schema_name: str, table: str) -> dict:
    """Generate a plausible row for INSERT without trying to parse SQL values.

    The earlier implementation stored `{}`, which later appeared in SELECT
    results and exposed the deception. This returns a deterministic fake row
    using an offset beyond the base table count so primary keys do not collide
    with ordinary generated rows.
    """
    if not table:
        return {}
    table_def = _schema_loader.get_table(schema_name, table)
    if not table_def:
        return {}
    columns_def = _schema_loader.get_columns(schema_name, table)
    base_count = _generator.generate_count(
        table_def.get("row_count", 100), (principal_seed.get() or req.session_id), table
    )
    inserted_count = len(_mutations.get_inserted_rows(req.session_id, table))
    rows = _generator.generate_rows(
        columns=columns_def,
        row_count=base_count + inserted_count + 1,
        session_id=(principal_seed.get() or req.session_id),
        table_name=table,
        limit=1,
        offset=base_count + inserted_count,
    )
    return rows[0] if rows else {}


def _extract_table(fp: str) -> str:
    """Best-effort table name extraction from normalised fingerprint."""
    match = re.search(
        r"\b(?:from|into|update|join)\s+([a-z_][a-z0-9_$]*(?:\.[a-z_][a-z0-9_$]*)?)",
        str(fp or ""), re.I,
    )
    if match:
        return match.group(1).split(".")[-1].lower()
    return ""


def _parse_id_predicate(query: str) -> int | None:
    """Parse the supported bounded row predicate: WHERE [alias.]id = integer."""
    match = re.search(r"\bwhere\s+(.+)$", str(query or ""), re.I)
    if not match:
        return None
    predicate = re.split(r"\s+(?:limit|offset)\s+", match.group(1), maxsplit=1, flags=re.I)[0]
    predicate = predicate.strip().rstrip(";").strip()
    bounded = re.fullmatch(
        r"(?:(?:[a-z_][a-z0-9_]*)\.)?id\s*=\s*(\d+)",
        predicate, re.I,
    )
    return int(bounded.group(1)) if bounded else None


def _parse_select_projection(query: str, available: list[str]) -> list[str]:
    """Return a simple identifier-only SELECT projection or the safe full row."""
    match = re.search(r"\bselect\s+(.*?)\s+from\s+", str(query or ""), re.I)
    if not match:
        return list(available)
    expressions = match.group(1).strip()
    if expressions == "*" or expressions.endswith(".*"):
        return list(available)
    projected: list[str] = []
    for expression in expressions.split(",")[:len(available)]:
        expression = re.sub(r"\s+as\s+[a-z_][a-z0-9_]*$", "", expression.strip(), flags=re.I)
        identifier = expression.split(".")[-1].strip(' `"')
        if identifier in available and identifier not in projected:
            projected.append(identifier)
    return projected or list(available)


def _parse_update_assignments(query: str, available: set[str]) -> dict:
    """Parse bounded column assignments; no expressions beyond +/- numeric."""
    match = re.search(r"\bset\s+(.+?)\s+where\b", str(query or ""), re.I)
    if not match:
        return {}
    assignments: dict[str, dict] = {}
    for expression in match.group(1).split(",")[:16]:
        expression = expression.strip()
        relative = re.fullmatch(
            r"([a-z_][a-z0-9_]*)\s*=\s*\1\s*([+-])\s*(-?\d+(?:\.\d+)?)",
            expression, re.I,
        )
        if relative:
            column = relative.group(1).lower()
            if column not in available:
                return {}
            raw_value = relative.group(3)
            value = float(raw_value) if "." in raw_value else int(raw_value)
            assignments[column] = {
                "op": "add" if relative.group(2) == "+" else "subtract",
                "value": value,
            }
            continue

        literal = re.fullmatch(
            r"([a-z_][a-z0-9_]*)\s*=\s*(null|true|false|-?\d+(?:\.\d+)?|'(?:''|[^'])*')",
            expression, re.I,
        )
        if not literal:
            return {}
        column = literal.group(1).lower()
        if column not in available or column == "id":
            return {}
        raw_value = literal.group(2)
        lowered = raw_value.lower()
        if lowered == "null":
            value = None
        elif lowered in {"true", "false"}:
            value = lowered == "true"
        elif raw_value.startswith("'"):
            value = raw_value[1:-1].replace("''", "'")
        elif "." in raw_value:
            value = float(raw_value)
        else:
            value = int(raw_value)
        assignments[column] = {"op": "set", "value": value}
    return assignments


def _row_id_exists(
    req: DecisionRequest, schema_name: str, table: str, row_id: int
) -> bool:
    table_def = _schema_loader.get_table(schema_name, table)
    if not table_def or row_id < 1:
        return False
    base_count = _generator.generate_count(
        table_def.get("row_count", 100), (principal_seed.get() or req.session_id), table
    )
    exists = row_id <= base_count or any(
        row.get("id") == row_id
        for row in _mutations.get_inserted_rows(req.session_id, table)
    )
    if not exists:
        return False
    return bool(_mutations.apply_rows(req.session_id, table, [{"id": row_id}]))


def _parse_limit_offset(fp: str) -> tuple[int, int]:
    """Extract LIMIT and OFFSET from SQL text/fingerprint.

    Callers usually pass lowercased query_normalized, but tests and future proxy
    integrations may pass raw-ish SQL. Make the parser case-insensitive here so
    uppercase LIMIT/OFFSET does not silently fall back to 100 rows.
    """
    limit, offset = 100, 0
    text = (fp or "").lower()
    # MySQL also supports LIMIT offset,count. Prefer that form if present.
    lm_pair = re.search(r"limit\s+(\d+)\s*,\s*(\d+)", text)
    lm = re.search(r"limit\s+(\d+|\?)", text)
    om = re.search(r"offset\s+(\d+|\?)", text)
    if lm_pair:
        offset = int(lm_pair.group(1))
        limit = min(int(lm_pair.group(2)), 500)
    elif lm and lm.group(1) != "?":
        limit = min(int(lm.group(1)), 500)
    if om and om.group(1) != "?":
        offset = int(om.group(1))
    return limit, offset


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8001")),
        reload=False,
    )
