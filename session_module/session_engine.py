import time
import threading
import json
import logging
from collections import Counter
from models import SessionOutput
from feature_extractor import (
    shannon_entropy, compute_depth_score,
    compute_timing_variance_ms, compute_queries_per_second,
)
import config

from metrics import active_sessions, sessions_closed_total, session_entropy, session_depth_score

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suspicion probe patterns (Gap 2)
# Matched against the lowercased, stripped query fingerprint.
# ---------------------------------------------------------------------------
_SUSPICION_PROBES = [
    "select @@hostname",
    "select @@version_comment",
    "select @@datadir",
    "select @@basedir",
    "select @@secure_file_priv",
    "select @@global.version",
]

_SUSPICION_CONTAINS = [
    "sleep(",           # SELECT SLEEP(N)
    "benchmark(",       # SELECT BENCHMARK(N,expr)
    "load_file(",       # SELECT LOAD_FILE(...)
    "into outfile",     # SELECT ... INTO OUTFILE
    "into dumpfile",    # SELECT ... INTO DUMPFILE
]




def _normalise_protocol(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    if "mysql" in v:
        return "mysql"
    if v in ("pg", "postgres", "postgresql") or v.startswith("pg-") or v.startswith("postgres"):
        return "postgres"
    return v




def _fallback_session_id(source_ip: str, db_user: str, protocol: str = "", database: str = "") -> str:
    """Build a deterministic synthetic session ID for legacy events.

    Older events may not contain the proxy-generated session_id. Downstream
    consumers such as the MITRE agent use this same convention, so session
    profiles can still close the corresponding live in-memory state instead of
    becoming unrelated profile-only summaries.
    """
    proto = _normalise_protocol(protocol) or "db"
    ip = source_ip or "unknown"
    user = db_user or "unknown"
    db = database or ""
    return f"{proto}:{ip}:{user}:{db}" if db else f"{proto}:{ip}:{user}"

def _compute_suspicion_delta(fingerprint: str) -> int:
    """Returns 1 if this fingerprint matches a known probe pattern, else 0."""
    fp = fingerprint.lower().strip().rstrip(";").strip()
    if fp in _SUSPICION_PROBES:
        return 1
    for fragment in _SUSPICION_CONTAINS:
        if fragment in fp:
            return 1
    return 0


class ActiveSession:
    def __init__(self, source_ip, db_user, timestamp, session_id="", protocol="", database=""):
        self.source_ip = source_ip
        self.db_user = db_user
        self.session_id = session_id
        self.protocol = protocol
        self.database = database
        self.start_time = timestamp
        self.last_activity = timestamp

        self.fingerprint_counter = Counter()
        self.fingerprint_sequence = []

        self.failed_auth = 0
        self.query_count = 0

        self.read_query_count = 0
        self.write_query_count = 0

        # Gap 1 — timing
        self.query_timestamps: list = []

        # Gap 2 — suspicion
        self.suspicion_score: int = 0

    def update(self, event):
        # Replayed/multi-topic events can arrive slightly out of timestamp order.
        # Keep last_activity monotonic so timeout and duration calculations do
        # not go negative or close active sessions prematurely.
        if event.timestamp > self.last_activity:
            self.last_activity = event.timestamp

        if event.event_type in ("query", "recon_probe"):
            fp = event.query_fingerprint
            self.fingerprint_counter[fp] += 1
            self.fingerprint_sequence.append(fp)
            self.query_count += 1
            self.query_timestamps.append(event.timestamp)

            # Read/write classification
            if fp.lower().startswith("select"):
                self.read_query_count += 1
            else:
                self.write_query_count += 1

            # Suspicion scoring
            self.suspicion_score += _compute_suspicion_delta(fp)

        if event.event_type == "auth_fail":
            self.failed_auth += 1
            self.fingerprint_sequence.append("AUTH_FAIL")


class SessionEngine:
    def __init__(self, storage):
        self.active_sessions = {}
        self.storage = storage
        self.lock = threading.Lock()
        self.running = True

        # Daemon mode prevents a partially initialised test/dev process from
        # hanging forever if shutdown() is not reached. The real app still calls
        # shutdown() for a clean final flush.
        self.sweeper_thread = threading.Thread(target=self._timeout_sweeper, daemon=True)
        self.sweeper_thread.start()

    def _key(self, event):
        # Prefer the real proxy session_id. For legacy events without a session_id,
        # include protocol/database when available so concurrent MySQL and
        # PostgreSQL activity from the same IP/user does not collapse into one
        # synthetic session. Preserve the original (source_ip, db_user) fallback
        # for old tests and historic events that have no protocol metadata.
        protocol = _normalise_protocol(getattr(event, "protocol", ""))
        database = getattr(event, "database", "") or ""
        if getattr(event, "session_id", ""):
            return (protocol or "db", event.session_id)
        if protocol or database:
            return (protocol or "db", event.source_ip, event.db_user, database)
        return (event.source_ip, event.db_user)

    def process_event(self, event):
        key = self._key(event)
        session_to_close = None

        with self.lock:
            if key not in self.active_sessions:
                if len(self.active_sessions) >= config.MAX_ACTIVE_SESSIONS:
                    oldest_key = min(
                        self.active_sessions.items(),
                        key=lambda x: x[1].last_activity,
                    )[0]
                    session_to_close = self.active_sessions.pop(oldest_key, None)

                protocol = _normalise_protocol(getattr(event, "protocol", ""))
                database = getattr(event, "database", "") or ""
                session_id = getattr(event, "session_id", "") or _fallback_session_id(
                    event.source_ip, event.db_user, protocol, database
                )
                self.active_sessions[key] = ActiveSession(
                    event.source_ip, event.db_user, event.timestamp,
                    session_id=session_id,
                    protocol=protocol,
                    database=database,
                )
                active_sessions.set(len(self.active_sessions))

            session = self.active_sessions[key]
            if not session.protocol and getattr(event, "protocol", ""):
                session.protocol = _normalise_protocol(getattr(event, "protocol", ""))
            if not session.database and getattr(event, "database", ""):
                session.database = getattr(event, "database", "")
            session.update(event)

        # Kafka/storage I/O must happen outside the active-session lock. If the
        # broker stalls, new events should still be able to update/create sessions.
        if session_to_close:
            self._emit_closed_session(session_to_close)

    def close_session(self, key):
        with self.lock:
            session = self.active_sessions.pop(key, None)
            active_sessions.set(len(self.active_sessions))
        if not session:
            return
        self._emit_closed_session(session)

    def _emit_closed_session(self, session):
        duration = max(0.0, session.last_activity - session.start_time)
        entropy = shannon_entropy(session.fingerprint_counter)
        depth_score = compute_depth_score(session.fingerprint_counter.keys())

        unique_fp_count = len(session.fingerprint_counter)
        read_write_ratio = (
            session.read_query_count / session.query_count
            if session.query_count > 0 else 0.0
        )

        # Gap 1 — timing features
        timing_variance_ms = compute_timing_variance_ms(session.query_timestamps)
        queries_per_second = compute_queries_per_second(session.query_count, duration)

        output = SessionOutput(
            session_id=session.session_id,
            source_ip=session.source_ip,
            db_user=session.db_user,
            duration=duration,
            entropy=entropy,
            failed_auth=session.failed_auth,
            depth_score=depth_score,
            query_count=session.query_count,
            protocol=session.protocol,
            database=session.database,
            cluster_id=None,
            persona=None,
            created_at=time.time(),
            unique_fingerprint_count=unique_fp_count,
            read_query_count=session.read_query_count,
            write_query_count=session.write_query_count,
            read_write_ratio=read_write_ratio,
            fingerprints=json.dumps(list(session.fingerprint_counter.keys())),
            query_sequence=json.dumps(session.fingerprint_sequence),
            timing_variance_ms=timing_variance_ms,
            queries_per_second=queries_per_second,
            suspicion_score=session.suspicion_score,
        )

        logger.info(
            "session closed: session_id=%s source_ip=%s db_user=%s protocol=%s queries=%d failed_auth=%d entropy=%.3f depth=%.2f",
            output.session_id,
            output.source_ip,
            output.db_user,
            output.protocol,
            output.query_count,
            output.failed_auth,
            output.entropy,
            output.depth_score,
        )

        sessions_closed_total.inc()
        session_entropy.set(entropy)
        session_depth_score.set(depth_score)

        self.storage.save_session(output)

    def force_close_oldest(self):
        with self.lock:
            if not self.active_sessions:
                return
            oldest_key = min(
                self.active_sessions.items(),
                key=lambda x: x[1].last_activity,
            )[0]
            session = self.active_sessions.pop(oldest_key, None)
            active_sessions.set(len(self.active_sessions))
        if session:
            self._emit_closed_session(session)

    def _timeout_sweeper(self):
        while self.running:
            time.sleep(1)
            now = time.time()

            with self.lock:
                keys_to_close = [
                    key for key, session in self.active_sessions.items()
                    if now - session.last_activity > config.SESSION_TIMEOUT
                ]
                sessions_to_close = [
                    self.active_sessions.pop(key, None) for key in keys_to_close
                ]
                active_sessions.set(len(self.active_sessions))

            for session in sessions_to_close:
                if session:
                    self._emit_closed_session(session)

    def flush_all(self):
        with self.lock:
            sessions_to_close = list(self.active_sessions.values())
            self.active_sessions.clear()
            active_sessions.set(0)

        for session in sessions_to_close:
            self._emit_closed_session(session)

    def shutdown(self):
        self.running = False
        self.sweeper_thread.join(timeout=2)
        self.flush_all()
