"""
models.py — Dataclasses for the MITRE Intelligence Agent.

All fields that come from the session module are documented with their source.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import hashlib
import uuid
import time
from datetime import datetime


def _timestamp_bucket(value: object) -> str:
    if isinstance(value, (int, float)):
        return str(int(float(value)))
    text = str(value or "").strip()
    try:
        return str(int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()))
    except (TypeError, ValueError):
        return text


def make_mitre_event_id(
    session_id: str,
    technique_id: str,
    rule_id: str,
    timestamp: object,
    query_identity: str,
) -> str:
    """Build a deterministic identity that remains stable across Kafka replay."""
    material = "\0".join(
        str(part or "").strip()
        for part in (
            session_id,
            technique_id,
            rule_id,
            _timestamp_bucket(timestamp),
            query_identity,
        )
    )
    return f"mitre:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


# ─── Inbound event (from query-events topics) ─────────────────────────────────

@dataclass
class QueryEvent:
    """Normalised query event consumed from mysql-query-events or pg-query-events."""
    session_id:       str
    timestamp:        float          # epoch float
    client_ip:        str
    username:         str
    database:         str
    query_raw:        str
    query_normalized: str
    fingerprint:      str            # FNV-64a hex from proxy interceptor
    protocol_mode:    str            # "text" | "prepared" | "recon_probe"
    event_type:       str            # "query" | "recon_probe" | "auth_fail"
    protocol:         str = ""       # "mysql" | "postgres" when known
    phase:            str = ""       # from phase_classifier: recon/enumeration/...
    bytes_in:         int = 0
    bytes_out:        int = 0
    outcome_verified: bool = False
    success:          bool = False
    authority:        str = ""
    event_schema_version: str = ""
    world_id:         str = ""
    asset_id:         str = ""
    asset_kind:       str = ""
    trap_triggered:   bool = False
    trap_id:          str = ""
    trap_kind:        str = ""
    trap_mitre_technique_id: str = ""
    trap_risk_score:  float = 0.0
    strategy_id:      str = ""
    strategy_registry_version: str = ""


# ─── Session profile (from session-profiles topic) ────────────────────────────

@dataclass
class SessionProfile:
    """Enriched session profile published by the session module after DBSCAN."""
    session_id:          str
    source_ip:           str
    db_user:             str
    duration:            float        # seconds
    query_count:         int
    failed_auth:         int
    entropy:             float        # Shannon entropy of fingerprint distribution
    depth_score:         int          # unique fingerprint count
    timing_variance_ms:  float        # stdev of inter-query gaps
    queries_per_second:  float
    suspicion_score:     int          # honeypot-detection probe counter
    read_write_ratio:    float
    cluster_id:          Optional[int]
    persona:             str          # brute_bot/automated_tool/human_attacker/script
    fingerprints:        str          # JSON list
    query_sequence:      str          # JSON list
    protocol:            str = ""
    database:            str = ""


# ─── Rule evaluation context ───────────────────────────────────────────────────

@dataclass
class EvalContext:
    """
    Unified context passed to the rule engine for evaluation.
    Combines the current query event with the accumulated session state.
    """
    # From current query event
    fingerprint:         str
    phase:               str
    event_type:          str
    table:               str = ""    # extracted from query_normalized if available
    trap_triggered:      bool = False
    trap_mitre_technique_id: str = ""
    trap_risk_score:     float = 0.0

    # From session (accumulated so far)
    session_id:          str = ""
    client_ip:           str = ""
    query_count:         int = 0
    timing_variance_ms:  float = 0.0
    qps:                 float = 0.0
    entropy:             float = 0.0
    depth_score:         int = 0
    failed_auth:         int = 0
    suspicion_score:     int = 0
    risk_score:          float = 0.0
    attack_path:         list[str] = field(default_factory=list)
    fingerprint_reuse:   int = 0     # how many times this fingerprint seen in session


# ─── MITRE technique match ─────────────────────────────────────────────────────

@dataclass
class TechniqueMatch:
    """Single MITRE ATT&CK technique matched against a query event."""
    technique_id:   str           # e.g. "T1082"
    technique_name: str
    tactic:         str           # e.g. "Discovery"
    tactic_id:      str           # e.g. "TA0007"
    confidence:     float         # 0.0 – 1.0
    matched_by:     str           # "fingerprint" | "phase" | "threshold" | "trap"
    explanation:    str           # human-readable reason
    rule_id:        str = ""      # detection rule id, e.g. R003_schema_enumeration


# ─── Per-event MITRE output ────────────────────────────────────────────────────

@dataclass
class MitreEvent:
    """
    Published to mitre-events topic for every query event.
    Kafka key: session_id (same partition → ordered).
    """
    session_id:          str
    timestamp:           str          # ISO-8601
    client_ip:           str
    fingerprint:         str
    phase:               str
    technique_id:        str
    technique_name:      str
    tactic:              str
    tactic_id:           str
    rule_id:             str          # which rule fired, e.g. "R001"
    rule_confidence:     float
    event_id:            str = ""     # deterministic replay/idempotency identity
    sequence_confidence: float = 0.0  # filled in by HMM at session close
    combined_confidence: float = 0.0  # 0.6 * rule + 0.4 * sequence
    risk_score:          float = 0.0  # accumulated session risk at this point
    risk_level:          str = "low"  # low/medium/high/critical
    deception_level:     int = 1      # 1-4, forwarded to deception engine
    tags:                list[str] = field(default_factory=list)
    explanation:         str = ""
    is_trap_triggered:   bool = False
    protocol:            str = ""       # mysql/postgres when known
    database:            str = ""
    event_schema_version: str = ""
    world_id:            str = ""
    asset_id:            str = ""
    asset_kind:          str = ""
    trap_id:             str = ""
    trap_kind:           str = ""
    trap_mitre_technique_id: str = ""
    trap_risk_score:     float = 0.0
    strategy_id:         str = ""
    strategy_registry_version: str = ""


# ─── Session-level MITRE summary ──────────────────────────────────────────────

@dataclass
class MitreSession:
    """
    Published to mitre-events once at session close.
    Contains the full attack chain, HMM score, and actor profile update signal.
    """
    session_id:          str
    client_ip:           str
    username:            str
    protocol:            str
    database:            str
    timestamp_closed:    str
    duration_s:          float
    final_risk_score:    float
    risk_level:          str
    persona:             str
    attack_path:         list[str]    # ordered list of phases seen
    techniques_matched:  list[dict]   # list of TechniqueMatch as dicts
    sequence_confidence: float        # HMM Viterbi output
    attack_graph:        dict         # NetworkX node_link_data
    trap_triggered:      bool
    trap_tables_accessed: list[str]
    explanation:         str


# ─── Actor profile (cross-session, keyed by IP) ───────────────────────────────

@dataclass
class ActorProfile:
    """
    Persisted in Redis, keyed by client_ip.
    Tracks cumulative risk across all sessions from the same IP.
    """
    ip:                  str
    first_seen:          str          # ISO-8601
    last_seen:           str
    session_count:       int = 0
    cumulative_risk:     float = 0.0
    phase_history:       list[str] = field(default_factory=list)   # all phases ever seen
    techniques_seen:     list[str] = field(default_factory=list)   # all technique IDs
    personas_seen:       list[str] = field(default_factory=list)
    trap_triggers:       int = 0
    is_known_attacker:   bool = False

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())
