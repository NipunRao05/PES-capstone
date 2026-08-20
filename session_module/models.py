from dataclasses import dataclass, field
from collections import Counter
from typing import List, Optional
import time
import uuid


# ===============================
# Incoming Event Model
# ===============================
@dataclass
class Event:
    timestamp: float
    source_ip: str
    db_user: str
    query_fingerprint: str
    event_type: str        # "query", "auth_fail", or "recon_probe"
    phase: str = ""        # MITRE attack phase — empty for normal queries
    session_id: str = ""   # proxy session_id when available; fallback uses source_ip/db_user
    protocol: str = ""     # "mysql" | "postgres" when available
    database: str = ""


# ===============================
# Internal Active Session Model
# (Used only inside SessionEngine)
# ===============================
@dataclass
class Session:
    source_ip: str
    db_user: str
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    query_count: int = 0
    failed_auth_count: int = 0

    fingerprint_counter: Counter = field(default_factory=Counter)
    fingerprint_sequence: List[str] = field(default_factory=list)

    read_query_count: int = 0
    write_query_count: int = 0

    def update(self, event: "Event"):
        # Legacy Session objects are used by feature-extraction tests and local
        # simulations. Keep last_seen monotonic just like ActiveSession so
        # replayed/out-of-order events cannot shorten the session.
        if event.timestamp > self.last_seen:
            self.last_seen = event.timestamp

        if event.event_type == "auth_fail":
            self.failed_auth_count += 1
            self.fingerprint_sequence.append("AUTH_FAIL")
            return

        self.query_count += 1
        self.fingerprint_counter[event.query_fingerprint] += 1
        self.fingerprint_sequence.append(event.query_fingerprint)

        if event.query_fingerprint.lower().startswith("select"):
            self.read_query_count += 1
        else:
            self.write_query_count += 1


# ===============================
# Final Persisted Session Output
# ===============================
@dataclass
class SessionOutput:
    session_id: str
    source_ip: str
    db_user: str
    duration: float
    entropy: float
    failed_auth: int
    depth_score: float
    query_count: int
    protocol: str = ""
    database: str = ""

    cluster_id: Optional[int] = None
    persona: Optional[str] = None

    created_at: float = field(default_factory=time.time)

    # Behavioral fields
    unique_fingerprint_count: int = 0
    read_query_count: int = 0
    write_query_count: int = 0
    read_write_ratio: float = 0.0
    fingerprints: str = ""
    query_sequence: str = ""

    # Timing features (Gap 1)
    timing_variance_ms: float = 0.0
    queries_per_second: float = 0.0

    # Suspicion score (Gap 2)
    suspicion_score: int = 0

    @staticmethod
    def new_id():
        return str(uuid.uuid4())