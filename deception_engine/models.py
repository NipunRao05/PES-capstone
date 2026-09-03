"""
models.py — Request/response dataclasses for the deception engine API.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class DecisionRequest:
    """Sent by the proxy shaper to /decide for every intercepted query."""
    session_id:       str
    query_normalized: str
    fingerprint:      str
    event_type:       str        # "query" | "recon_probe" | "auth_fail"
    phase:            str        # from phase_classifier
    username:         str
    database:         str
    protocol:         str = "mysql"  # "mysql" | "postgres"
    table:            str = ""       # extracted table name if available
    deception_level:  int = 1    # from mitre-events (1–4)
    risk_score:       float = 0.0
    transaction_state: str = "idle"  # idle | in_transaction | failed_transaction


@dataclass
class DecisionResponse:
    """Returned by /decide — tells the proxy what to do."""
    mode:        str             # "passthrough" | "fake" | "block" | "delay"
    rows:        list[dict] = field(default_factory=list)
    count:       Optional[int] = None
    affected_rows: Optional[int] = None
    columns:     list[str] = field(default_factory=list)
    column_types: list[str] = field(default_factory=list)
    tables:      list[str] = field(default_factory=list)   # for SHOW TABLES
    databases:   list[str] = field(default_factory=list)   # for SHOW DATABASES
    latency_ms:  int = 0
    error_msg:   str = ""
    error_code:  int = 0
    sqlstate:    str = ""
    profile:     str = ""        # which deception profile was applied
    explanation: str = ""
    is_trap:     bool = False
    # Structured v2 outcome metadata. ``trap_triggered`` means the attacker
    # received a successful response from that trap; mere catalogue visibility
    # must never set it.
    event_schema_version: str = "deception-decision-v2"
    world_id:    str = ""
    asset_id:    str = ""
    asset_kind:  str = ""
    trap_triggered: bool = False
    trap_id:     str = ""
    trap_kind:   str = ""
    trap_mitre_technique_id: str = ""
    trap_risk_score: float = 0.0
    strategy_id: str = "D0"
    strategy_registry_version: str = ""


@dataclass
class BannerResponse:
    """Returned for system variable queries (@@hostname etc.)."""
    value: str
