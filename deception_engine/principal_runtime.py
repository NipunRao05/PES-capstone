"""Private proxy-to-engine API for bounded synthetic authentication/state.

The existing /decide never receives credentials. This router's errors never
include request bodies, password proofs, Redis values, or exception text.
"""
import json
import re
import time
import redis
from contextvars import ContextVar
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from principal_registry import PrincipalRegistry, PrincipalError, PREFIX, SESSION_TTL, now
from principal_state import PrincipalTransactionContext, PrincipalTransactionConflict
from world_commitments import Commitments, Fact, FIELD

principal_seed = ContextVar("principal_seed", default="")


def failure(error):
    return {"mode": "block", "error_msg": str(error), "sqlstate": error.state,
            "error_code": error.code, "profile": "deceptive_principal", "strategy_id": "D0"}


def success(**fields):
    return {"mode": "fake", "profile": "deceptive_principal", "strategy_id": "D0", **fields}


def install(app, api):
    # Principal traffic has a stricter budget than legacy best-effort /decide.
    principal_redis = None
    def registry():
        nonlocal principal_redis
        if principal_redis is None:
            principal_redis = redis.Redis(host=api.REDIS_HOST, port=api.REDIS_PORT,
                decode_responses=True, socket_connect_timeout=0.4, socket_timeout=0.4,
                retry_on_timeout=False)
        return PrincipalRegistry(principal_redis)

    @app.post("/principals/{action}")
    async def principal_action(action: str, request: Request):
        reg = registry()
        if not reg.trusted(request.headers.get("X-Deceptive-Principal-Key", "")):
            raise HTTPException(403, "Account service unavailable")
        try:
            raw = await request.body()
            if len(raw) > 70000:
                raise PrincipalError("Request too large", "54000", 1153)
            body = json.loads(raw)
            reg.deadline_ms = min(float(body.get("deadline_ms", 0)), time.time() * 1000 + 2500)
            reg.check_deadline()
            sid = body.get("session_id", "")
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", sid):
                raise PrincipalError("Invalid session")
            if action == "command":
                return success(**reg.command(body))
            if action == "scram-start":
                return reg.start_scram(body)
            if action == "scram-finish":
                return reg.finish_scram(body)
            if action == "native-auth":
                return reg.native_auth(body)
            if action == "query":
                return await query(reg, api, request, body)
            if action == "observe":
                return observe(reg, api, body)
            if action == "end":
                end_session(reg, api, sid)
                return {"status": "ok"}
            raise PrincipalError("Unsupported operation")
        except PrincipalError as exc:
            return JSONResponse(failure(exc), status_code=400 if action in {"scram-start", "scram-finish", "native-auth"} else 200)
        except Exception:
            # Never log exception text: libraries can embed request/Redis values.
            return JSONResponse(failure(PrincipalError("Account service unavailable", "58000", 1045)), status_code=503)

    @app.get("/principals/metrics")
    async def principal_metrics():
        try:
            return registry().metrics()
        except Exception:
            raise HTTPException(503, "Account metrics unavailable")


def end_session(reg, api, sid):
    """Discard the binding and working state; never promote on disconnect.

    Both proxies call /principals/end from Run's deferred cleanup. Keep deletion
    first and the existing best-effort cleanup order, including repeated ends.
    """
    reg.redis.delete(PREFIX + "session:" + sid)
    api._exposure.cleanup_session(sid)
    api._mutations.cleanup_session(sid)
    api._generator.cleanup_session(sid)


def observe(reg, api, body):
    """Trusted proxy receipt after successful response writes; never a SQL action.

    Fresh record + existing principal lock preserves concurrent row revisions and
    prior facts. Observation alone must not invalidate an open SQL transaction.
    """
    sid = body["session_id"]
    session_key = PREFIX + "session:" + sid
    binding = json.loads(reg.redis.get(session_key) or "null")
    if not binding:
        raise PrincipalError("Session expired", "28000", 1045)
    candidates = body.get("observation_candidates")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 8:
        raise PrincipalError("Invalid observations")
    schema = api._schema_loader.schema_for_database("testdb")
    facts = []
    for subject in candidates:
        if not isinstance(subject, str) or not subject.startswith("testdb.") or not api._schema_loader.get_table(schema, subject[7:]):
            raise PrincipalError("Invalid observations")
        facts.append(Fact("relation", subject, "exists", True))
    with reg.lock(binding["key"]):
        current = json.loads(reg.redis.get(session_key) or "null")
        if not current or current["key"] != binding["key"]:
            raise PrincipalError("Session expired", "28000", 1045)
        record = reg.load(current["key"])
        # A response already sent remains observed even if the account was just
        # disabled. Do not re-enable it or alter its permissions/binding/TTL.
        commitments = Commitments(record)
        statuses = [commitments.commit(fact, session_id=sid, timestamp=now()) for fact in facts]
        inserted = statuses.count("inserted")
        if inserted:
            record[FIELD] = commitments.serialize()
            reg.save(current["key"], record)
        return {"status": "ok", "inserted": inserted, "conflicts": statuses.count("conflict")}


def observation_candidates(api, sql, result):
    """Only successful simple unqualified managed-table reads, including empty rows.

    Match a small grammar instead of inferring facts from arbitrary SQL/catalog
    results. These private candidates are not commitments or wire result fields.
    """
    if result.get("mode") != "fake" or result.get("profile") not in {"fake_table_data", "high_value_target"}:
        return []
    match = re.fullmatch(r"select\s+(?:\*|[a-z_][a-z0-9_]*(?:\s*,\s*[a-z_][a-z0-9_]*)*)\s+from\s+"
        r"([a-z_][a-z0-9_]{0,62})(?:\s+where\s+id\s*=\s*\d+)?(?:\s+limit\s+\d+)?", sql.lower())
    if match and api._schema_loader.get_table(api._schema_loader.schema_for_database("testdb"), match[1]):
        return ["testdb." + match[1]]
    return []


async def query(reg, api, request, body):
    sid = body["session_id"]
    session_key = PREFIX + "session:" + sid
    raw = reg.redis.get(session_key)
    if not raw:
        raise PrincipalError("Session expired", "28000", 1045)
    binding = json.loads(raw)
    with reg.lock(binding["key"]):
        # Re-read under the principal lock so concurrent requests cannot lose state.
        binding = json.loads(reg.redis.get(session_key) or "null")
        if not binding:
            raise PrincipalError("Session expired", "28000", 1045)
        transaction = PrincipalTransactionContext(binding)
        record = reg.load(binding["key"])
        if not record["enabled"]:
            raise PrincipalError("Account disabled", "28000", 1045)

        def working_keys():
            return list(reg.redis.scan_iter("mutation:" + sid + ":*", count=200))

        def expired_state():
            # Never promote a partial working world over durable committed state.
            # Reauthentication restores the committed record into a fresh session.
            reg.redis.delete(session_key)
            raise PrincipalError("Session state expired; reconnect required", "28000", 1045)

        if transaction.active:
            expected = transaction.expected_mutation_keys
            if expected is None or any(reg.redis.get(key) is None for key in expected):
                expired_state()

        def abort_statement():
            was_failed = transaction.failed
            transaction.record_query_failure(record["protocol"])
            if transaction.failed and not was_failed:
                reg.check_deadline()
                reg.redis.setex(session_key, SESSION_TTL, json.dumps(binding))

        # The trusted proxy can reject a statement locally (e.g. extended SQL),
        # without the registry having seen it. Reconcile before any promotion.
        if record["protocol"] == "postgres" and body.get("transaction_state") == "failed_transaction":
            abort_statement()
        sql = body.get("sql", "").strip().rstrip(";").strip()
        if len(sql) > 65536 or not sql or ";" in sql or "/*" in sql or "--" in sql:
            if record["protocol"] == "postgres":
                if transaction.failed:
                    return failure(PrincipalError("Transaction is aborted", "25P02", 1192)) | {"tx_status": "E"}
                abort_statement()
                return failure(PrincipalError("Unsupported statement", "42601", 1064)) | {"tx_status": transaction.state.value}
            raise PrincipalError("Unsupported statement", "42601", 1064)
        normalized = sql.lower()
        tx_command = normalized in {"begin", "start transaction", "commit", "rollback"}
        if transaction.failed and normalized not in {"rollback", "commit"}:
            return failure(PrincipalError("Transaction is aborted", "25P02", 1192)) | {"tx_status": "E"}

        def restore():
            keys = list(reg.redis.scan_iter("mutation:" + sid + ":*", count=200))
            with reg.redis.pipeline(transaction=True) as pipe:
                if keys:
                    pipe.delete(*keys)
                pipe.delete("mutation-tx:" + sid)
                for table, value in record["persistent_mutations"].items():
                    pipe.setex("mutation:" + sid + ":" + table, SESSION_TTL, value)
                pipe.hset("exposure:" + sid, mapping={"depth": record["exposure_depth"]})
                pipe.expire("exposure:" + sid, SESSION_TTL)
                pipe.execute()

        def promote():
            overlays = {}
            keys = set(working_keys()) | set(binding.get("mutation_keys", []))
            for key in keys:
                value = reg.redis.get(key)
                if value is None:
                    expired_state()
                overlays[key.split(":", 2)[2]] = value
            if len(json.dumps(overlays)) > 1024 * 1024:
                abort_statement()
                raise PrincipalError("Account state limit exceeded", "54000", 1114)
            record["persistent_mutations"] = overlays
            record["world_revision"] += 1

        if not transaction.active:
            restore()
            transaction.refresh_revision(record["world_revision"])
        if record["protocol"] == "mysql" and normalized in {"set names utf8mb4", "set names utf8", "set names utf8mb4 collate utf8mb4_general_ci"}:
            result = success(command_tag="SET", affected_rows=0)
        elif tx_command:
            tag = normalized.upper()
            if normalized in {"begin", "start transaction"}:
                transaction.begin()
                tag = "BEGIN"
            else:
                def discard_snapshot():
                    api._mutations.finalize_transaction(sid, "commit")

                if normalized == "commit":
                    try:
                        tag = transaction.commit(record["world_revision"], promote, discard_snapshot, restore)
                    except PrincipalTransactionConflict:
                        reg.redis.setex(session_key, SESSION_TTL, json.dumps(binding))
                        return failure(PrincipalError("Concurrent state change; rollback required", "40001", 1213)) | {"tx_status": "E"}
                else:
                    tag = transaction.rollback(discard_snapshot, restore)
            result = success(command_tag=tag, affected_rows=0)
        else:
            verb = normalized.split()[0].upper()
            if verb not in {"SELECT", "SHOW", "INSERT", "UPDATE", "DELETE"} or (verb != "SHOW" and verb not in record["persistent_permissions"]):
                result = failure(PrincipalError("Permission denied or unsupported operation", "42501", 1142))
            else:
                token = principal_seed.set(record["principal_key"])
                try:
                    response = await api.decide(request, {"session_id": sid,
                        "query_normalized": sql, "query_raw": sql, "protocol": record["protocol"],
                        "username": record["username"], "database": "testdb", "deception_level": 1,
                        "transaction_state": "in_transaction" if transaction.active else "idle"})
                    result = json.loads(response.body)
                except HTTPException:
                    abort_statement()
                    raise
                finally:
                    principal_seed.reset(token)
                if result.get("mode") != "fake" and result.get("mode") != "block":
                    result = failure(PrincipalError("Unsupported synthetic operation"))
                if result.get("mode") == "fake" and not transaction.active and verb in {"INSERT", "UPDATE", "DELETE"}:
                    promote()
            if result.get("mode") != "fake":
                transaction.record_query_failure(record["protocol"])
            record["exposure_depth"] = max(record["exposure_depth"], api._exposure.get_depth(sid))
        reg.check_deadline()
        record["updated_at"] = now()
        keys = working_keys()
        transaction.track_working_keys(keys)
        # One atomic durable write precedes the proxy's success response.
        with reg.redis.pipeline(transaction=True) as pipe:
            # Keep working overlays alive at least as long as the refreshed binding.
            for key in keys:
                pipe.expire(key, SESSION_TTL)
            pipe.expire("mutation-tx:" + sid, SESSION_TTL)
            pipe.expire("exposure:" + sid, SESSION_TTL)
            pipe.set(binding["key"], json.dumps(record))
            pipe.setex(session_key, SESSION_TTL, json.dumps(binding))
            pipe.execute()
        result["tx_status"] = transaction.state.value
        result["post_return_exploration_depth"] = record["exposure_depth"]
        candidates = observation_candidates(api, sql, result)
        if candidates:
            result["observation_candidates"] = candidates
        return result
