"""Persistent, bounded experiment assignment for the two-stage dynamic roadmap.

Dynamic Phase D1 deliberately does not control attacker-facing responses.  It
provides the durable control-plane primitives required before a later phase may
commit an attack path: sticky cohort assignment, global safe mode/operator
overrides, monotonic world revisions, and duplicate-event rejection.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


STATE_VERSION = 1
ASSIGNMENT_VERSION = "experiment-assignment-v1"
CONTROL_VERSION = "experiment-control-v1"
EXPERIMENT_ID = "two-stage-factorial-v1"

ARM_MODES = {
    "A": "STATIC_FIXED",
    "B": "ADAPTIVE_STEERING",
    "C": "STATIC_INTERVENTION",
    "D": "ADAPTIVE_STEERING_INTERVENTION",
}
VALID_ARMS = frozenset(ARM_MODES)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")

_MAX_SESSION_ID = 256
_MAX_PROTOCOL = 32
_MAX_COHORT_KEY = 512
_MAX_EVENT_ID = 256
_MAX_ACTOR = 128
_MAX_REASON = 512
_MAX_AUDIT = 200


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded(value: Any, limit: int) -> str:
    return str(value or "").replace("\x00", "").strip()[:limit]


def normalize_protocol(value: Any) -> str:
    protocol = _bounded(value, _MAX_PROTOCOL).lower()
    if "mysql" in protocol:
        return "mysql"
    if protocol in {"pg", "postgres", "postgresql"} or protocol.startswith("pg-") or "postgres" in protocol:
        return "postgres"
    return "unknown"


def assignment_key_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8", errors="replace")).hexdigest()


def default_control() -> dict[str, Any]:
    now = utc_now()
    return {
        "state_version": STATE_VERSION,
        "control_version": CONTROL_VERSION,
        "revision": 0,
        "safe_mode": False,
        "forced_arm": "",
        "updated_at": now,
        "audit": [],
    }


def validate_control(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("state_version") != STATE_VERSION:
        return None
    if value.get("control_version") != CONTROL_VERSION:
        return None
    revision = value.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        return None
    if not isinstance(value.get("safe_mode"), bool):
        return None
    forced_arm = value.get("forced_arm", "")
    if forced_arm not in VALID_ARMS and forced_arm != "":
        return None
    audit = value.get("audit")
    if not isinstance(audit, list) or len(audit) > _MAX_AUDIT:
        return None
    return copy.deepcopy(value)


def validate_assignment(value: Any, expected_session_id: str = "") -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    if value.get("state_version") != STATE_VERSION:
        return None
    if value.get("assignment_version") != ASSIGNMENT_VERSION:
        return None
    if value.get("experiment_id") != EXPERIMENT_ID:
        return None
    session_id = _bounded(value.get("session_id"), _MAX_SESSION_ID)
    if not session_id or (expected_session_id and session_id != expected_session_id):
        return None
    if value.get("protocol") not in {"postgres", "mysql", "unknown"}:
        return None
    if value.get("assigned_arm") not in VALID_ARMS:
        return None
    if value.get("assigned_mode") != ARM_MODES[value["assigned_arm"]]:
        return None
    if value.get("assignment_source") not in {
        "HMAC_COHORT", "OPERATOR_FORCED", "PERSISTENCE_FALLBACK"
    }:
        return None
    cohort_hmac = value.get("cohort_hmac", "")
    if value.get("assignment_source") != "PERSISTENCE_FALLBACK" and not (
        isinstance(cohort_hmac, str) and _HEX_64.fullmatch(cohort_hmac)
    ):
        return None
    for name in ("control_revision", "world_revision", "processed_event_count"):
        number = value.get(name)
        if not isinstance(number, int) or isinstance(number, bool) or number < 0:
            return None
    return copy.deepcopy(value)


@dataclass(frozen=True)
class EventClaim:
    status: str
    world_revision: int
    duplicate: bool = False
    persisted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "world_revision": self.world_revision,
            "duplicate": self.duplicate,
            "persisted": self.persisted,
        }


class InMemoryExperimentPersistence:
    """Deterministic test backend with the same atomic contracts as Redis."""

    def __init__(self, *, secret: str = "d1-test-secret-that-is-at-least-32-bytes"):
        self._secret = secret.encode("utf-8")
        self._control: dict[str, Any] | None = None
        self._assignments: dict[str, dict[str, Any]] = {}
        self._events: dict[str, list[str]] = {}
        self._event_sets: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    def ping(self) -> bool:
        return True

    def ensure_secret(self, explicit_secret: str = "") -> bytes:
        if explicit_secret:
            if len(explicit_secret.encode("utf-8")) < 32:
                raise ValueError("experiment assignment secret must be at least 32 bytes")
            self._secret = explicit_secret.encode("utf-8")
        return bytes(self._secret)

    def load_control(self) -> dict[str, Any] | None:
        with self._lock:
            return copy.deepcopy(self._control)

    def compare_set_control(self, expected_revision: int | None, value: dict[str, Any]) -> bool:
        with self._lock:
            current_revision = None if self._control is None else self._control.get("revision")
            if current_revision != expected_revision:
                return False
            self._control = copy.deepcopy(value)
            return True

    def get_assignment(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            return copy.deepcopy(self._assignments.get(session_id))

    def create_assignment(self, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            existing = self._assignments.get(value["session_id"])
            if existing is None:
                self._assignments[value["session_id"]] = copy.deepcopy(value)
                existing = value
            return copy.deepcopy(existing)

    def list_assignments(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            ordered = sorted(
                self._assignments.values(),
                key=lambda item: (item.get("updated_at", ""), item.get("session_id", "")),
                reverse=True,
            )
            return copy.deepcopy(ordered[:limit])

    def claim_event(
        self,
        session_id: str,
        event_id: str,
        expected_revision: int,
        advance_revision: bool,
        max_events: int,
        block_new: bool = False,
    ) -> EventClaim:
        with self._lock:
            assignment = self._assignments.get(session_id)
            if assignment is None:
                return EventClaim("SESSION_NOT_FOUND", 0, persisted=False)
            current = int(assignment["world_revision"])
            event_set = self._event_sets.setdefault(session_id, set())
            if event_id in event_set:
                return EventClaim("DUPLICATE", current, duplicate=True)
            if block_new:
                return EventClaim("SAFE_MODE", current)
            if current != expected_revision:
                return EventClaim("STALE_REVISION", current)
            events = self._events.setdefault(session_id, [])
            events.append(event_id)
            event_set.add(event_id)
            while len(events) > max_events:
                event_set.discard(events.pop(0))
            if advance_revision:
                current += 1
            assignment["world_revision"] = current
            assignment["processed_event_count"] = len(events)
            assignment["updated_at"] = utc_now()
            return EventClaim("ACCEPTED", current)

    def count_assignments(self) -> int:
        with self._lock:
            return len(self._assignments)

    def close(self) -> None:
        return


class RedisExperimentPersistence:
    """Redis-backed atomic storage. Redis is imported lazily for test isolation."""

    _CLAIM_EVENT_SCRIPT = """
local assignment_raw = redis.call('GET', KEYS[1])
if not assignment_raw then return {'SESSION_NOT_FOUND', '0'} end
local assignment = cjson.decode(assignment_raw)
local current = tonumber(assignment['world_revision']) or 0
if redis.call('SISMEMBER', KEYS[2], ARGV[1]) == 1 then
  return {'DUPLICATE', tostring(current)}
end
if ARGV[6] == '1' then return {'SAFE_MODE', tostring(current)} end
if current ~= tonumber(ARGV[2]) then
  return {'STALE_REVISION', tostring(current)}
end
redis.call('SADD', KEYS[2], ARGV[1])
redis.call('RPUSH', KEYS[3], ARGV[1])
while redis.call('LLEN', KEYS[3]) > tonumber(ARGV[3]) do
  local evicted = redis.call('LPOP', KEYS[3])
  if evicted then redis.call('SREM', KEYS[2], evicted) end
end
if ARGV[4] == '1' then current = current + 1 end
assignment['world_revision'] = current
assignment['processed_event_count'] = redis.call('LLEN', KEYS[3])
assignment['updated_at'] = ARGV[5]
redis.call('SET', KEYS[1], cjson.encode(assignment))
return {'ACCEPTED', tostring(current)}
"""
    _CREATE_ASSIGNMENT_SCRIPT = """
local existing = redis.call('GET', KEYS[1])
if existing then return existing end
redis.call('SET', KEYS[1], ARGV[1])
redis.call('ZADD', KEYS[2], ARGV[2], KEYS[1])
return ARGV[1]
"""

    def __init__(
        self,
        host: str,
        port: int,
        db: int,
        key_prefix: str,
        timeout_seconds: float,
        password: str = "",
    ):
        import redis

        self._redis_module = redis
        self._client = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password or None,
            socket_connect_timeout=timeout_seconds,
            socket_timeout=timeout_seconds,
            decode_responses=True,
        )
        self._prefix = key_prefix.rstrip(":") or "capstone:dynamic-experiment:v1"

    @property
    def _control_key(self) -> str:
        return f"{self._prefix}:control"

    @property
    def _secret_key(self) -> str:
        return f"{self._prefix}:assignment-secret"

    @property
    def _index_key(self) -> str:
        return f"{self._prefix}:assignments"

    def _assignment_key(self, session_id: str) -> str:
        return f"{self._prefix}:assignment:{assignment_key_hash(session_id)}"

    def _event_keys(self, session_id: str) -> tuple[str, str]:
        key_hash = assignment_key_hash(session_id)
        return (
            f"{self._prefix}:processed-events:{key_hash}",
            f"{self._prefix}:processed-event-order:{key_hash}",
        )

    def ping(self) -> bool:
        return bool(self._client.ping())

    def ensure_secret(self, explicit_secret: str = "") -> bytes:
        if explicit_secret:
            encoded = explicit_secret.encode("utf-8")
            if len(encoded) < 32:
                raise ValueError("experiment assignment secret must be at least 32 bytes")
            return encoded
        candidate = secrets.token_hex(32)
        self._client.set(self._secret_key, candidate, nx=True)
        stored = self._client.get(self._secret_key)
        if not isinstance(stored, str) or len(stored) < 32:
            raise RuntimeError("could not provision persistent experiment assignment secret")
        return stored.encode("utf-8")

    def load_control(self) -> dict[str, Any] | None:
        raw = self._client.get(self._control_key)
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def compare_set_control(self, expected_revision: int | None, value: dict[str, Any]) -> bool:
        for _ in range(5):
            with self._client.pipeline() as pipe:
                try:
                    pipe.watch(self._control_key)
                    raw = pipe.get(self._control_key)
                    if raw is None:
                        current_revision = None
                    else:
                        try:
                            current_revision = json.loads(raw).get("revision")
                        except (TypeError, ValueError, AttributeError):
                            return False
                    if current_revision != expected_revision:
                        return False
                    pipe.multi()
                    pipe.set(
                        self._control_key,
                        json.dumps(value, sort_keys=True, separators=(",", ":")),
                    )
                    pipe.execute()
                    return True
                except self._redis_module.WatchError:
                    continue
        return False

    def get_assignment(self, session_id: str) -> dict[str, Any] | None:
        raw = self._client.get(self._assignment_key(session_id))
        if raw is None:
            return None
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            return None
        return value if isinstance(value, dict) else None

    def create_assignment(self, value: dict[str, Any]) -> dict[str, Any]:
        session_id = value["session_id"]
        key = self._assignment_key(session_id)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        stored = self._client.eval(
            self._CREATE_ASSIGNMENT_SCRIPT,
            2,
            key,
            self._index_key,
            encoded,
            datetime.now(timezone.utc).timestamp(),
        )
        try:
            result = json.loads(stored)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("assignment atomic creation returned invalid state") from exc
        if not isinstance(result, dict):
            raise RuntimeError("assignment atomic creation returned a non-object")
        return result

    def list_assignments(self, limit: int) -> list[dict[str, Any]]:
        keys = self._client.zrevrange(self._index_key, 0, max(0, limit - 1))
        if not keys:
            return []
        values = self._client.mget(keys)
        records: list[dict[str, Any]] = []
        for raw in values:
            try:
                value = json.loads(raw) if raw else None
            except (TypeError, ValueError):
                value = None
            if isinstance(value, dict):
                records.append(value)
        return records

    def claim_event(
        self,
        session_id: str,
        event_id: str,
        expected_revision: int,
        advance_revision: bool,
        max_events: int,
        block_new: bool = False,
    ) -> EventClaim:
        event_set, event_order = self._event_keys(session_id)
        result = self._client.eval(
            self._CLAIM_EVENT_SCRIPT,
            3,
            self._assignment_key(session_id),
            event_set,
            event_order,
            event_id,
            expected_revision,
            max_events,
            1 if advance_revision else 0,
            utc_now(),
            1 if block_new else 0,
        )
        status = str(result[0])
        revision = int(result[1])
        return EventClaim(
            status,
            revision,
            duplicate=status == "DUPLICATE",
            persisted=status != "SESSION_NOT_FOUND",
        )

    def count_assignments(self) -> int:
        return int(self._client.zcard(self._index_key))

    def close(self) -> None:
        self._client.close()


class ExperimentAssignmentController:
    """Validated experiment control plane with deterministic safe fallback."""

    def __init__(
        self,
        persistence: Any | None,
        *,
        explicit_secret: str = "",
        persistence_required: bool = True,
        max_processed_events: int = 10_000,
    ):
        self.persistence = persistence
        self.persistence_required = bool(persistence_required)
        self.max_processed_events = min(max(1, int(max_processed_events)), 100_000)
        self._secret = b""
        self._available = False
        self._last_error = ""
        self._lock = threading.RLock()
        try:
            if persistence is None or not persistence.ping():
                raise RuntimeError("experiment persistence unavailable")
            self._secret = persistence.ensure_secret(explicit_secret)
            self._ensure_control()
            self._available = True
        except Exception as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"[:512]

    def _ensure_control(self) -> dict[str, Any]:
        current = self.persistence.load_control()
        if current is not None:
            valid = validate_control(current)
            if valid is None:
                raise RuntimeError("invalid persisted experiment control state")
            return valid
        initial = default_control()
        if self.persistence.compare_set_control(None, initial):
            return initial
        current = validate_control(self.persistence.load_control())
        if current is None:
            raise RuntimeError("could not initialize experiment control state")
        return current

    def _mark_error(self, exc: Exception) -> None:
        self._last_error = f"{type(exc).__name__}: {exc}"[:512]
        # A persistence error removes all dynamic authority until restart.  Do
        # not optimistically continue after a split-brain or Redis timeout.
        self._available = False

    def persistence_ok(self) -> bool:
        return self._available

    def readiness_ok(self) -> bool:
        return self._available or not self.persistence_required

    def control(self) -> dict[str, Any]:
        if not self._available:
            fallback = default_control()
            fallback["safe_mode"] = True
            fallback["degraded"] = True
            return fallback
        try:
            control = validate_control(self.persistence.load_control())
            if control is None:
                raise RuntimeError("invalid persisted experiment control state")
            control["degraded"] = False
            return control
        except Exception as exc:
            self._mark_error(exc)
            fallback = default_control()
            fallback["safe_mode"] = True
            fallback["degraded"] = True
            return fallback

    def status(self) -> dict[str, Any]:
        control = self.control()
        assignment_count = 0
        if self._available:
            try:
                assignment_count = self.persistence.count_assignments()
            except Exception as exc:
                self._mark_error(exc)
        return {
            "state_version": STATE_VERSION,
            "assignment_version": ASSIGNMENT_VERSION,
            "control_version": CONTROL_VERSION,
            "experiment_id": EXPERIMENT_ID,
            "persistence_required": self.persistence_required,
            "persistence_available": self._available,
            "safe_mode": bool(control["safe_mode"]),
            "forced_arm": control["forced_arm"],
            "control_revision": control["revision"],
            "assignment_count": assignment_count,
            "max_processed_events_per_session": self.max_processed_events,
            "dynamic_execution_enabled": False,
            "steering_authority": False,
            "intervention_authority": False,
            "last_error": self._last_error,
        }

    def _cohort_hmac(self, protocol: str, cohort_key: str) -> str:
        material = f"{protocol}\x1f{cohort_key}".encode("utf-8", errors="replace")
        return hmac.new(self._secret, material, hashlib.sha256).hexdigest()

    @staticmethod
    def _arm_for_hmac(cohort_hmac: str) -> str:
        return tuple(sorted(VALID_ARMS))[int(cohort_hmac[:16], 16) % len(VALID_ARMS)]

    @staticmethod
    def _with_effective_control(assignment: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(assignment)
        result["safe_mode"] = bool(control["safe_mode"])
        result["effective_mode"] = "SAFE_MODE" if control["safe_mode"] else assignment["assigned_mode"]
        result["new_dynamic_commits_allowed"] = False
        result["dynamic_execution_enabled"] = False
        result["control_revision_current"] = control["revision"]
        return result

    @staticmethod
    def _fallback_assignment(session_id: str, protocol: str) -> dict[str, Any]:
        now = utc_now()
        return {
            "state_version": STATE_VERSION,
            "assignment_version": ASSIGNMENT_VERSION,
            "experiment_id": EXPERIMENT_ID,
            "session_id": session_id,
            "protocol": protocol,
            "cohort_hmac": "",
            "assigned_arm": "A",
            "assigned_mode": ARM_MODES["A"],
            "assignment_source": "PERSISTENCE_FALLBACK",
            "control_revision": 0,
            "world_revision": 0,
            "processed_event_count": 0,
            "created_at": now,
            "updated_at": now,
            "persisted": False,
            "safe_mode": True,
            "effective_mode": "SAFE_MODE",
            "new_dynamic_commits_allowed": False,
            "dynamic_execution_enabled": False,
            "control_revision_current": 0,
        }

    def assign(self, session_id: Any, protocol: Any, cohort_key: Any) -> dict[str, Any]:
        session = _bounded(session_id, _MAX_SESSION_ID)
        if not session:
            raise ValueError("session_id is required")
        normalized_protocol = normalize_protocol(protocol)
        cohort = _bounded(cohort_key, _MAX_COHORT_KEY) or session
        if not self._available:
            return self._fallback_assignment(session, normalized_protocol)
        try:
            existing = validate_assignment(self.persistence.get_assignment(session), session)
            control = self.control()
            if existing is not None:
                existing["persisted"] = True
                return self._with_effective_control(existing, control)
            cohort_hmac = self._cohort_hmac(normalized_protocol, cohort)
            arm = control["forced_arm"] or self._arm_for_hmac(cohort_hmac)
            now = utc_now()
            candidate = {
                "state_version": STATE_VERSION,
                "assignment_version": ASSIGNMENT_VERSION,
                "experiment_id": EXPERIMENT_ID,
                "session_id": session,
                "protocol": normalized_protocol,
                "cohort_hmac": cohort_hmac,
                "assigned_arm": arm,
                "assigned_mode": ARM_MODES[arm],
                "assignment_source": "OPERATOR_FORCED" if control["forced_arm"] else "HMAC_COHORT",
                "control_revision": control["revision"],
                "world_revision": 0,
                "processed_event_count": 0,
                "created_at": now,
                "updated_at": now,
            }
            stored = validate_assignment(self.persistence.create_assignment(candidate), session)
            if stored is None:
                raise RuntimeError("persistence returned an invalid assignment")
            stored["persisted"] = True
            return self._with_effective_control(stored, self.control())
        except Exception as exc:
            self._mark_error(exc)
            return self._fallback_assignment(session, normalized_protocol)

    def get_assignment(self, session_id: Any) -> dict[str, Any] | None:
        session = _bounded(session_id, _MAX_SESSION_ID)
        if not session or not self._available:
            return None
        try:
            assignment = validate_assignment(self.persistence.get_assignment(session), session)
            if assignment is None:
                return None
            assignment["persisted"] = True
            return self._with_effective_control(assignment, self.control())
        except Exception as exc:
            self._mark_error(exc)
            return None

    def list_assignments(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 250))
        if not self._available:
            return []
        try:
            control = self.control()
            records = []
            for value in self.persistence.list_assignments(limit):
                assignment = validate_assignment(value)
                if assignment is not None:
                    assignment["persisted"] = True
                    records.append(self._with_effective_control(assignment, control))
            return records
        except Exception as exc:
            self._mark_error(exc)
            return []

    def claim_event(
        self,
        session_id: Any,
        event_id: Any,
        expected_revision: Any,
        *,
        advance_revision: bool = False,
    ) -> dict[str, Any]:
        session = _bounded(session_id, _MAX_SESSION_ID)
        event = _bounded(event_id, _MAX_EVENT_ID)
        if not session or not event:
            return EventClaim("INVALID_INPUT", 0, persisted=False).to_dict()
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            return EventClaim("INVALID_INPUT", 0, persisted=False).to_dict()
        control = self.control()
        assignment = self.get_assignment(session)
        current = int(assignment["world_revision"]) if assignment else 0
        if not self._available:
            return EventClaim("PERSISTENCE_UNAVAILABLE", current, persisted=False).to_dict()
        try:
            return self.persistence.claim_event(
                session,
                event,
                expected_revision,
                bool(advance_revision),
                self.max_processed_events,
                bool(control["safe_mode"] and advance_revision),
            ).to_dict()
        except Exception as exc:
            self._mark_error(exc)
            return EventClaim("PERSISTENCE_UNAVAILABLE", current, persisted=False).to_dict()

    def _mutate_control(
        self,
        action: str,
        actor: Any,
        reason: Any,
        mutator: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        actor_text = _bounded(actor, _MAX_ACTOR)
        reason_text = _bounded(reason, _MAX_REASON)
        if not actor_text or not reason_text:
            raise ValueError("actor and reason are required")
        if not self._available:
            raise RuntimeError("experiment persistence unavailable")
        with self._lock:
            for _ in range(5):
                current = validate_control(self.persistence.load_control())
                if current is None:
                    raise RuntimeError("invalid persisted experiment control state")
                updated = copy.deepcopy(current)
                mutator(updated)
                updated["revision"] = current["revision"] + 1
                updated["updated_at"] = utc_now()
                audit = list(current["audit"])
                audit.append({
                    "audit_id": hashlib.sha256(
                        f"{action}\x1f{updated['revision']}\x1f{actor_text}\x1f{reason_text}".encode("utf-8")
                    ).hexdigest()[:24],
                    "action": action,
                    "actor": actor_text,
                    "reason": reason_text,
                    "previous": {
                        "safe_mode": current["safe_mode"],
                        "forced_arm": current["forced_arm"],
                        "revision": current["revision"],
                    },
                    "current": {
                        "safe_mode": updated["safe_mode"],
                        "forced_arm": updated["forced_arm"],
                        "revision": updated["revision"],
                    },
                    "timestamp": updated["updated_at"],
                })
                updated["audit"] = audit[-_MAX_AUDIT:]
                if self.persistence.compare_set_control(current["revision"], updated):
                    result = validate_control(updated)
                    assert result is not None
                    result["degraded"] = False
                    return result
            raise RuntimeError("experiment control update conflicted repeatedly")

    def set_safe_mode(self, enabled: Any, actor: Any, reason: Any) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be boolean")
        return self._mutate_control(
            "set_safe_mode", actor, reason,
            lambda control: control.__setitem__("safe_mode", enabled),
        )

    def set_forced_arm(self, arm: Any, actor: Any, reason: Any) -> dict[str, Any]:
        normalized = _bounded(arm, 1).upper()
        if normalized not in VALID_ARMS and normalized != "":
            raise ValueError("arm must be A, B, C, D, or empty")
        return self._mutate_control(
            "set_forced_arm" if normalized else "clear_forced_arm",
            actor,
            reason,
            lambda control: control.__setitem__("forced_arm", normalized),
        )

    def rollback_safe(self, actor: Any, reason: Any) -> dict[str, Any]:
        def mutate(control: dict[str, Any]) -> None:
            control["safe_mode"] = True
            control["forced_arm"] = "A"
        return self._mutate_control("rollback_safe", actor, reason, mutate)

    def close(self) -> None:
        if self.persistence is not None:
            try:
                self.persistence.close()
            except Exception as exc:
                self._mark_error(exc)
