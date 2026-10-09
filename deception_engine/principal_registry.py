"""Durable synthetic identities. Native verifiers stay inside deception Redis.

Only reserved fake_ accounts are managed. Every write/auth/query is serialized
by the same Redis principal lock. No SQL is executed against a physical engine.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone

ORIGIN = "attacker_created_deceptive"
PREFIX = "deceptive-principal:"
SESSION_TTL = 14400
NAME = r"fake_[a-z0-9_]{1,48}"


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    return base64.b64decode(value, validate=True)


def now():
    return datetime.now(timezone.utc).isoformat()


class PrincipalError(Exception):
    def __init__(self, message="Operation is not available", state="0A000", code=1235):
        super().__init__(message)
        self.state, self.code = state, code


class PrincipalRegistry:
    def __init__(self, redis, secret=None):
        self.redis = redis
        self.deadline_ms = None
        self.secret_text = secret if secret is not None else os.getenv("DECEPTIVE_PRINCIPAL_HMAC_SECRET", "")
        try:
            self.secret = unb64(self.secret_text)
        except Exception:
            self.secret = b""
        self.enabled = len(self.secret) >= 32

    def check_deadline(self):
        if self.deadline_ms is not None and time.time() * 1000 >= self.deadline_ms:
            raise PrincipalError("Account operation timed out", "57014", 1317)

    def require_enabled(self):
        if not self.enabled:
            raise PrincipalError("Account management is unavailable", "55000", 1045)

    def trusted(self, supplied):
        return self.enabled and hmac.compare_digest(supplied or "", self.secret_text)

    def key(self, protocol, username):
        self.require_enabled()
        if protocol not in {"postgres", "mysql"} or not re.fullmatch(NAME, username):
            raise PrincipalError("Unsupported account name")
        digest = hmac.new(self.secret, (protocol + ":" + username).encode(), hashlib.sha256).hexdigest()
        return PREFIX + digest

    def load(self, key):
        raw = self.redis.get(key)
        if not raw:
            raise PrincipalError("Account is unavailable", "28000", 1045)
        return json.loads(raw)

    def lock(self, key):
        return self.redis.lock(key + ":lock", timeout=15, blocking_timeout=2)

    def save(self, key, record):
        self.check_deadline()
        record["updated_at"] = now()
        self.redis.set(key, json.dumps(record, separators=(",", ":")))

    def verifier(self, protocol, password):
        # ASCII subset deliberately avoids ambiguous SASLprep/password encodings.
        if not re.fullmatch(r"[!-~]{8,128}", password) or "'" in password or "\\" in password:
            raise PrincipalError("Unsupported password format", "22023", 1819)
        salt = secrets.token_bytes(16)
        if protocol == "postgres":
            salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
            client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
            return {"method": "SCRAM-SHA-256", "salt": b64(salt), "iterations": 4096,
                    "stored_key": b64(hashlib.sha256(client).digest()),
                    "server_key": b64(hmac.new(salted, b"Server Key", hashlib.sha256).digest())}
        stage2 = hashlib.sha1(hashlib.sha1(password.encode()).digest()).digest()
        return {"method": "mysql_native_password", "stage2": b64(stage2), "salt_context": b64(salt)}

    @staticmethod
    def context(record):
        return {"deceptive_principal_id": record["principal_id"], "principal_origin": ORIGIN,
                "creator_session_id": record["created_by_session_id"], "is_return_session": True}

    def event(self, kind, record, sid, **extra):
        return {"event_type": kind, "event_id": secrets.token_hex(16), "session_id": sid,
                "timestamp": now(), "protocol": record["protocol"], "principal_id": record["principal_id"],
                "principal_origin": ORIGIN, **extra}

    def command(self, body):
        self.require_enabled()
        protocol, username, sid = body["protocol"], body["username"], body["session_id"]
        if body.get("transaction_active"):
            raise PrincipalError("Account statements require autocommit", "25001", 1192)
        # Only the world's existing seeded administrator has apparent CREATE/GRANT authority.
        if username != {"postgres": "postgres", "mysql": "root"}.get(protocol):
            raise PrincipalError("Permission denied", "42501", 1227)
        sql = body.get("sql", "").strip().rstrip(";").strip()
        if len(sql) > 1024 or any(x in sql for x in (";", "--", "/*", "*/", "\\")):
            raise PrincipalError("Unsupported account statement", "42601", 1064)
        target = "(" + NAME + ")"
        if protocol == "mysql":
            target = "(?:" + target + "|'" + target + "')(?:@'%')?"
            create = re.fullmatch(r"CREATE USER " + target + r" IDENTIFIED BY '([^']+)'", sql, re.I)
            password = re.fullmatch(r"ALTER USER " + target + r" IDENTIFIED BY '([^']+)'", sql, re.I)
            disable = re.fullmatch(r"ALTER USER " + target + r" ACCOUNT LOCK", sql, re.I)
            drop = re.fullmatch(r"DROP USER " + target, sql, re.I)
            grant = re.fullmatch(r"GRANT (SELECT(?:, ?(?:INSERT|UPDATE|DELETE))*) ON testdb[.]\* TO " + target, sql, re.I)
        else:
            create = re.fullmatch(r"CREATE (?:USER " + target + r"(?: WITH)?|ROLE " + target + r" LOGIN) PASSWORD '([^']+)'", sql, re.I)
            password = re.fullmatch(r"ALTER (?:USER|ROLE) " + target + r"(?: WITH)? PASSWORD '([^']+)'", sql, re.I)
            disable = re.fullmatch(r"ALTER (?:USER|ROLE) " + target + r" NOLOGIN", sql, re.I)
            drop = re.fullmatch(r"DROP (?:USER|ROLE) " + target, sql, re.I)
            grant = re.fullmatch(r"GRANT (SELECT(?:, ?(?:INSERT|UPDATE|DELETE))*) ON ALL TABLES IN SCHEMA public TO " + target, sql, re.I)
        match = create or password or disable or drop or grant
        if not match:
            raise PrincipalError("Unsupported account statement", "42601", 1064)
        values = [v for v in match.groups() if v is not None]
        target_name = (values[-1] if grant else values[0]).lower()
        key = self.key(protocol, target_name)
        with self.lock(key):
            if create:
                if self.redis.exists(key):
                    raise PrincipalError("Account already exists", "42710", 1396)
                verifier = self.verifier(protocol, values[-1])
                material = (protocol + ":" + target_name + ":" + json.dumps(verifier, sort_keys=True)).encode()
                principal_key = hmac.new(self.secret, material, hashlib.sha256).hexdigest()
                record = {"principal_id": "DP-" + principal_key, "principal_key": principal_key,
                    "username": target_name, "protocol": protocol, "principal_origin": ORIGIN,
                    "created_by_session_id": sid, "created_by_principal_id": "",
                    "created_at": now(), "updated_at": now(), "last_login_at": None,
                    "enabled": True, "visible_role": "reader", "persistent_permissions": ["SELECT"],
                    "strategy_id": "D0", "world_id": "", "world_revision": 0, "exposure_depth": 1,
                    "persistent_objects": {}, "persistent_mutations": {}, "login_count": 0,
                    "linked_session_ids": [], "credential_revision": 1, "verifier": verifier,
                    "first_reuse_at": None, "time_to_first_reuse_seconds": None}
                self.check_deadline()
                with self.redis.pipeline(transaction=True) as pipe:
                    pipe.set(key, json.dumps(record))
                    pipe.sadd(PREFIX + "created", record["principal_id"])
                    pipe.execute()
                event = self.event("deceptive_principal_created", record, sid,
                    created_by_session_id=sid, created_by_principal_id="")
                return {"events": [event], "command_tag": "CREATE ROLE" if protocol == "postgres" else "CREATE USER"}
            record = self.load(key)
            if password:
                record["verifier"] = self.verifier(protocol, values[-1])
                record["credential_revision"] += 1
            elif disable or drop:
                record["enabled"] = False
            elif grant:
                record["persistent_permissions"] = sorted(set(v.strip().upper() for v in values[0].split(",")))
                record["visible_role"] = "writer" if len(record["persistent_permissions"]) > 1 else "reader"
            self.save(key, record)
            return {"events": [], "command_tag": "GRANT" if grant else "DROP ROLE" if drop else "ALTER ROLE"}

    def start_scram(self, body):
        key = self.key("postgres", body["username"])
        record = self.load(key)
        if not record["enabled"]:
            raise PrincipalError("Authentication failed", "28P01", 1045)
        first = body.get("client_first", "")
        match = re.fullmatch(r"(n|y),,n=[^,]{0,64},r=([!-+\--~]{16,128})", first)
        if not match:
            raise PrincipalError("Authentication failed", "28P01", 1045)
        verifier = record["verifier"]
        nonce = match[2] + secrets.token_hex(18)
        server = "r=" + nonce + ",s=" + verifier["salt"] + ",i=" + str(verifier["iterations"])
        token = secrets.token_hex(32)
        challenge = {"key": key, "session_id": body["session_id"], "first": first[3:],
            "channel": b64(first[:3].encode()), "server": server, "nonce": nonce,
            "credential_revision": record["credential_revision"]}
        self.check_deadline()
        self.redis.setex(PREFIX + "challenge:" + token, 30, json.dumps(challenge))
        return {"token": token, "server_first": server}

    def finish_scram(self, body):
        token = body.get("token", "")
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            raise PrincipalError("Authentication failed", "28P01", 1045)
        raw = self.redis.getdel(PREFIX + "challenge:" + token)
        if not raw:
            raise PrincipalError("Authentication failed", "28P01", 1045)
        challenge = json.loads(raw)
        with self.lock(challenge["key"]):
            record = self.load(challenge["key"])
            final = body.get("client_final", "")
            prefix = "c=" + challenge["channel"] + ",r=" + challenge["nonce"]
            if not final.startswith(prefix + ",p=") or len(final) > 512 or not record["enabled"] or record["credential_revision"] != challenge["credential_revision"]:
                raise PrincipalError("Authentication failed", "28P01", 1045)
            proof = unb64(final[len(prefix) + 3:])
            auth = (challenge["first"] + "," + challenge["server"] + "," + prefix).encode()
            stored = unb64(record["verifier"]["stored_key"])
            signature = hmac.new(stored, auth, hashlib.sha256).digest()
            client = bytes(a ^ b for a, b in zip(proof, signature))
            if len(proof) != 32 or not hmac.compare_digest(hashlib.sha256(client).digest(), stored):
                raise PrincipalError("Authentication failed", "28P01", 1045)
            server = hmac.new(unb64(record["verifier"]["server_key"]), auth, hashlib.sha256).digest()
            return {**self.login(challenge["key"], record, challenge["session_id"]), "server_final": "v=" + b64(server)}

    def native_auth(self, body):
        key = self.key("mysql", body["username"])
        with self.lock(key):
            record = self.load(key)
            salt, token = unb64(body["salt"]), unb64(body["auth_token"])
            if not record["enabled"] or len(salt) != 20 or len(token) != 20:
                raise PrincipalError("Authentication failed", "28000", 1045)
            stage2 = unb64(record["verifier"]["stage2"])
            scramble = hashlib.sha1(salt + stage2).digest()
            stage1 = bytes(a ^ b for a, b in zip(token, scramble))
            if not hmac.compare_digest(hashlib.sha1(stage1).digest(), stage2):
                raise PrincipalError("Authentication failed", "28000", 1045)
            return self.login(key, record, body["session_id"])

    def login(self, key, record, sid):
        session_key = PREFIX + "session:" + sid
        if sid == record["created_by_session_id"] or self.redis.exists(session_key):
            raise PrincipalError("Authentication failed", "28000", 1045)
        record["login_count"] += 1
        record["last_login_at"] = now()
        record["updated_at"] = now()
        record["linked_session_ids"] = (record["linked_session_ids"] + [sid])[-256:]
        if record["first_reuse_at"] is None:
            record["first_reuse_at"] = now()
            record["time_to_first_reuse_seconds"] = max(0, time.time() - datetime.fromisoformat(record["created_at"]).timestamp())
        binding = {"key": key, "tx": False, "failed": False, "revision": record["world_revision"]}
        self.check_deadline()
        with self.redis.pipeline(transaction=True) as pipe:
            pipe.set(key, json.dumps(record))
            pipe.setex(session_key, SESSION_TTL, json.dumps(binding))
            pipe.sadd(PREFIX + "reused", record["principal_id"])
            pipe.incr(PREFIX + "returns")
            pipe.execute()
        return {**self.context(record), "events": [
            self.event("deceptive_principal_authenticated", record, sid,
                time_to_first_reuse_seconds=record["time_to_first_reuse_seconds"], return_session_number=record["login_count"]),
            self.event("session_link", record, sid, relationship="credential_persistence",
                parent_session_id=record["created_by_session_id"], child_session_id=sid, confidence=1.0,
                reason="authenticated using attacker-created deceptive principal")]}

    def metrics(self):
        self.require_enabled()
        created = self.redis.scard(PREFIX + "created")
        reused = self.redis.scard(PREFIX + "reused")
        return {"deceptive_principals_created_total": created, "deceptive_principals_reused_total": reused,
            "deceptive_principal_return_sessions_total": int(self.redis.get(PREFIX + "returns") or 0),
            "deceptive_persistence_reengagement_rate": reused / created if created else 0.0}
