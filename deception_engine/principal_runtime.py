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
            if action == "end":
                reg.redis.delete(PREFIX + "session:" + sid)
                api._exposure.cleanup_session(sid)
                api._mutations.cleanup_session(sid)
                api._generator.cleanup_session(sid)
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
        record = reg.load(binding["key"])
        if not record["enabled"]:
            raise PrincipalError("Account disabled", "28000", 1045)
        sql = body.get("sql", "").strip().rstrip(";").strip()
        if len(sql) > 65536 or not sql or ";" in sql or "/*" in sql or "--" in sql:
            raise PrincipalError("Unsupported statement", "42601", 1064)
        normalized = sql.lower()
        tx_command = normalized in {"begin", "start transaction", "commit", "rollback"}
        if binding["failed"] and normalized not in {"rollback", "commit"}:
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
            for key in reg.redis.scan_iter("mutation:" + sid + ":*", count=200):
                overlays[key.split(":", 2)[2]] = reg.redis.get(key)
            if len(json.dumps(overlays)) > 1024 * 1024:
                raise PrincipalError("Account state limit exceeded", "54000", 1114)
            record["persistent_mutations"] = overlays
            record["world_revision"] += 1

        if not binding["tx"]:
            restore()
            binding["revision"] = record["world_revision"]
        if record["protocol"] == "mysql" and normalized in {"set names utf8mb4", "set names utf8", "set names utf8mb4 collate utf8mb4_general_ci"}:
            result = success(command_tag="SET", affected_rows=0)
        elif tx_command:
            tag = normalized.upper()
            if normalized in {"begin", "start transaction"}:
                binding["tx"] = True
                tag = "BEGIN"
            else:
                if normalized == "commit" and binding["tx"] and not binding["failed"]:
                    if binding["revision"] != record["world_revision"]:
                        binding["failed"] = True
                        reg.redis.setex(session_key, SESSION_TTL, json.dumps(binding))
                        return failure(PrincipalError("Concurrent state change; rollback required", "40001", 1213)) | {"tx_status": "E"}
                    promote()
                elif normalized == "commit" and binding["failed"]:
                    tag = "ROLLBACK"
                binding["tx"], binding["failed"] = False, False
                api._mutations.finalize_transaction(sid, "commit")
                restore()
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
                        "transaction_state": "in_transaction" if binding["tx"] else "idle"})
                    result = json.loads(response.body)
                finally:
                    principal_seed.reset(token)
                if result.get("mode") != "fake" and result.get("mode") != "block":
                    result = failure(PrincipalError("Unsupported synthetic operation"))
                if result.get("mode") == "fake" and not binding["tx"] and verb in {"INSERT", "UPDATE", "DELETE"}:
                    promote()
            if result.get("mode") != "fake" and binding["tx"] and record["protocol"] == "postgres":
                binding["failed"] = True
            record["exposure_depth"] = max(record["exposure_depth"], api._exposure.get_depth(sid))
        reg.check_deadline()
        record["updated_at"] = now()
        # One atomic durable write precedes the proxy's success response.
        with reg.redis.pipeline(transaction=True) as pipe:
            pipe.set(binding["key"], json.dumps(record))
            pipe.setex(session_key, SESSION_TTL, json.dumps(binding))
            pipe.execute()
        result["tx_status"] = "E" if binding["failed"] else "T" if binding["tx"] else "I"
        result["post_return_exploration_depth"] = record["exposure_depth"]
        return result
