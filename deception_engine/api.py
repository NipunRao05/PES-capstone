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

import dataclasses
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
BANNER_VERSION_COMMENT = os.environ.get("DECEPTION_VERSION_COMMENT", "MySQL Community Server - GPL")
BANNER_VERSION        = os.environ.get("DECEPTION_VERSION",         "8.0.34-log")
BANNER_PORT           = os.environ.get("DECEPTION_PORT",            "3306")
POSTGRES_VERSION      = os.environ.get("DECEPTION_POSTGRES_VERSION",  "PostgreSQL 16.2 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit")
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
}

# ─── App startup ──────────────────────────────────────────────────────────────

_redis_client: redis.Redis | None = None
_schema_loader: SchemaLoader | None = None
_generator: DataGenerator | None = None
_exposure: ExposureTracker | None = None
_mutations: MutationStore | None = None
_strategy_registry: StrategyRegistry = StrategyRegistry.load_with_fallback()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _redis_client, _schema_loader, _generator, _exposure, _mutations, _strategy_registry
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
        or " from information_schema.schemata" in fp
    ):
        if " from information_schema.schemata" in fp:
            return _json_response(DecisionResponse(
                mode="fake",
                databases=FAKE_DATABASES,
                rows=[{"schema_name": db} for db in FAKE_DATABASES],
                columns=["schema_name"],
                latency_ms=_latency(req.deception_level, base=30),
                profile="fake_schema",
                strategy_id="D1",
            ))
        if req.protocol.lower().startswith("postgres") or " from pg_database" in fp:
            return _json_response(DecisionResponse(
                mode="fake",
                databases=FAKE_DATABASES,
                rows=[{"datname": db} for db in FAKE_DATABASES],
                columns=["datname"],
                latency_ms=_latency(req.deception_level, base=30),
                profile="fake_schema",
                strategy_id="D1",
            ))
        return _json_response(DecisionResponse(
            mode="fake",
            databases=FAKE_DATABASES,
            rows=[{"Database": db} for db in FAKE_DATABASES],
            columns=["Database"],
            latency_ms=_latency(req.deception_level, base=30),
            profile="fake_schema",
            strategy_id="D1",
        ))

    # 3. Table enumeration — progressive exposure. Support common MySQL and
    # PostgreSQL catalog queries.
    if (
        "show tables" in fp
        or "show full tables" in fp
        or " from pg_tables" in fp
        or " from information_schema.tables" in fp
    ):
        return await _handle_show_tables(req, schema_name)

    # 4. COUNT(*) query
    if _is_count_query(fp):
        return await _handle_count(req, fp, schema_name)

    table = req.table or _extract_table(fp)

    # 5. Managed mutations must be classified before generic table reads.
    # The handlers already existed, but the earlier branch order made them
    # unreachable for known fake tables and returned SELECT-shaped rows instead.
    if _is_mutation(fp):
        return await _handle_mutation(req, fp, table, schema_name)

    # 6. SELECT from a known fake table
    if table and _schema_loader.get_table(schema_name, table):
        return await _handle_select(req, table, schema_name)

    # 7. SELECT from unknown table — passthrough to real backend
    return _json_response(DecisionResponse(
        mode="passthrough",
        explanation="Table not in fake schema — forwarding to backend",
    ))


# ─── Handlers ─────────────────────────────────────────────────────────────────

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
        rows = [{"Tables_in_db": t} for t in visible]
        columns = ["Tables_in_db"]

    return _json_response(DecisionResponse(
        mode="fake",
        tables=visible,
        rows=rows,
        columns=columns,
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

    # Advance depth on table access
    table_depth = table_def.get("exposure_depth", 1)
    _exposure.record_table_access(req.session_id, table, table_depth)

    base_count = _generator.generate_count(
        table_def.get("row_count", 100), req.session_id, table
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

    # Advance exploration depth
    table_depth = table_def.get("exposure_depth", 1)
    _exposure.record_table_access(req.session_id, table, table_depth)

    columns_def = _schema_loader.get_columns(schema_name, table)
    # Use the same deterministic effective count as COUNT(*) so pagination
    # probes cannot easily detect a mismatch between count and rows.
    base_count = _generator.generate_count(
        table_def.get("row_count", 100), req.session_id, table
    )
    # DELETE/INSERT mutations should affect SELECT pagination as well as
    # COUNT(*). Inserted rows are prepended below when offset=0; row_count still
    # needs the same adjusted total so high-offset probes do not reveal a
    # mismatch after mutations.
    row_count = max(0, base_count + _mutations.get_count_delta(req.session_id, table))
    limit, offset = _parse_limit_offset(req.query_normalized)

    # Cap rows — never return more than 100 regardless of LIMIT
    effective_limit = min(limit, 100)

    rows = _generator.generate_rows(
        columns=columns_def,
        row_count=row_count,
        session_id=req.session_id,
        table_name=table,
        limit=effective_limit,
        offset=offset,
    )

    # Prepend any inserted rows (mutation store)
    inserted = _mutations.get_inserted_rows(req.session_id, table)
    if inserted and offset == 0:
        rows = inserted[:effective_limit] + rows[:max(0, effective_limit - len(inserted))]

    col_names = [c["name"] for c in columns_def]
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
    if not table or not _schema_loader.get_table(schema_name, table):
        return _json_response(DecisionResponse(
            mode="passthrough",
            explanation="Mutation target is not in fake schema — forwarding to backend",
        ))

    if fp.startswith("insert"):
        row = _fake_insert_row(req, schema_name, table)
        if row:
            _mutations.record_insert(req.session_id, table, row)
        affected = 1
    elif fp.startswith("update"):
        _mutations.record_update(req.session_id, table, "", "")
        affected = random.randint(1, 5)
    elif fp.startswith("delete"):
        _mutations.record_delete(req.session_id, table, "")
        affected = random.randint(1, 3)
    else:
        affected = 0

    return _json_response(DecisionResponse(
        mode="fake",
        rows=[],
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
    return {"status": "ok"}


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
            latency_ms=_latency(req.deception_level, base=25),
            profile="fake_system_info",
            explanation=f"PostgreSQL banner hardening: {fp} → {column}='{value}'",
        ))

    if fp in SYSTEM_VAR_MAP:
        val = SYSTEM_VAR_MAP[fp]
        return _json_response(DecisionResponse(
            mode="fake",
            rows=[{"value": val}],
            columns=["value"],
            latency_ms=_latency(req.deception_level, base=25),
            profile="fake_system_info",
            explanation=f"Banner hardening: {fp} → '{val}'",
        ))
    return None


def _strategy_id_for_table(schema_name: str, table_name: str) -> str:
    """Map only existing approved assets; unknown assets stay on D0."""
    return _strategy_registry.strategy_for_asset(
        schema_name, table_name
    ).strategy_id


def _json_response(resp: DecisionResponse) -> JSONResponse:
    import dataclasses
    resolved = _strategy_registry.resolve(resp.strategy_id)
    resp.strategy_id = resolved.strategy_id
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
        table_def.get("row_count", 100), req.session_id, table
    )
    inserted_count = len(_mutations.get_inserted_rows(req.session_id, table))
    rows = _generator.generate_rows(
        columns=columns_def,
        row_count=base_count + inserted_count + 1,
        session_id=req.session_id,
        table_name=table,
        limit=1,
        offset=base_count + inserted_count,
    )
    return rows[0] if rows else {}


def _extract_table(fp: str) -> str:
    """Best-effort table name extraction from normalised fingerprint."""
    for keyword in (" from ", " into ", " update ", " join "):
        idx = fp.find(keyword)
        if idx >= 0:
            rest = fp[idx + len(keyword):].strip()
            token = rest.split()[0] if rest.split() else ""
            return token.strip("`'\";,()").split(".")[-1].strip("`'\";,()")
    return ""


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