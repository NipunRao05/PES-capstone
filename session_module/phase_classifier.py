"""
phase_classifier.py — Maps normalised SQL fingerprints to MITRE attack phases.
Called by redpanda_consumer for every event before it enters the pipeline.

Phases (6 total, matching Week 8 HMM states):
    recon               — system info / version / config queries
    enumeration         — schema discovery via information_schema / SHOW
    privilege_discovery — user / permission / grant inspection
    data_discovery      — reading actual table data (SELECT from app tables)
    exploitation        — file reads, timing attacks, injection probes
    exfiltration        — data dumps, file writes, bulk pagination

Returns None for ordinary application queries that have no attack phase signal.
"""

from __future__ import annotations

# ─── System table allowlist ────────────────────────────────────────────────────
# Queries targeting these tables are never classified as data_discovery.
# They fall through to enumeration, privilege_discovery, or None instead.
_SYSTEM_TABLES = frozenset({
    "information_schema",
    "performance_schema",
    "mysql",
    "sys",
    "pg_catalog",
    "pg_toast",
    "pg_temp",
})

# ─── Rule sets (checked in priority order) ────────────────────────────────────

# Recon: system variable reads, version/config inspection
_RECON_PATTERNS = (
    "select @@",
    "select version()",
    "select @@version",
    "select @@hostname",
    "select @@datadir",
    "select @@version_comment",
    "select @@global.",
    "select @@session.",
    "select inet_server_addr()",
    "select pg_postmaster_start_time()",
    "show variables",
    "show status",
    "show plugins",
    "show engines",
    "show master status",
    "show slave status",
    "show binary logs",
)

# Enumeration: schema-level discovery
_ENUMERATION_PATTERNS = (
    "show databases",
    "show schemas",
    "show tables",
    "show full tables",
    "show columns",
    "show full columns",
    "show create table",
    "show index",
    "information_schema.tables",
    "information_schema.columns",
    "information_schema.schemata",
    "information_schema.statistics",
    "information_schema.key_column_usage",
    "information_schema.table_constraints",
    "information_schema.routines",
    "information_schema.triggers",
    "pg_tables",
    "pg_views",
    "pg_indexes",
    "pg_namespace",
    "pg_class",
)

# Privilege discovery: user/permission inspection
_PRIVILEGE_PATTERNS = (
    "mysql.user",
    "mysql.db",
    "mysql.tables_priv",
    "mysql.columns_priv",
    "mysql.procs_priv",
    "select user()",
    "select current_user",
    "select current_user()",
    "select system_user()",
    "select session_user()",
    "show grants",
    "show grants for",
    "select * from pg_roles",
    "select * from pg_user",
    "select * from pg_shadow",
    "select * from pg_auth",
    "information_schema.role_table_grants",
    "information_schema.role_column_grants",
    "information_schema.user_privileges",
    "information_schema.schema_privileges",
    "information_schema.table_privileges",
)

# Exploitation: file ops, timing attacks, injection probes
_EXPLOITATION_PATTERNS = (
    "select load_file(",
    "load_file(?)",
    "select pg_read_file(",
    "pg_read_file(?)",
    "select sleep(",
    "sleep(?)",
    "select benchmark(",
    "benchmark(?)",
    "select pg_sleep(",
    "pg_sleep(?)",
    "waitfor delay",
    "1=1",
    "1=2",
    "or 1=",
    "and 1=",
    "union select null",
    "union select null,null",
    "order by ?--",
    "sys_exec(",
    "sys_eval(",
    "call sys.exec",
)

# Exfiltration: data write-out, bulk dumps, file writes
_EXFILTRATION_PATTERNS = (
    "into outfile",
    "into dumpfile",
    "into outfile ?",
    "into dumpfile ?",
    "copy ? to",
    "copy to stdout",
    r"\copy",
)

# Data discovery: reading actual application table rows.
# This is matched AFTER all system-table patterns above, so
# information_schema queries are already caught by enumeration.
# Any SELECT from a non-system table signals data_discovery.
_DATA_DISCOVERY_SELECT_PREFIXES = (
    "select *",
    "select count(*)",
    "select count(?)",
)

# Tables that are explicitly flagged as trap/honeytoken tables.
# These also trigger data_discovery (the attacker found the bait).
TRAP_TABLES = frozenset({
    "api_keys_backup",
    "salary_executives",
    "prod_credentials",
    "admin_tokens",
    "backup_passwords",
    "payment_tokens",
    "credit_cards_archive",
    "internal_api_keys",
    "aws_credentials",
})


def classify(fingerprint: str) -> str | None:
    """
    Returns the MITRE attack phase string for the given normalised fingerprint,
    or None if the query has no attack-phase signal.

    Fingerprint is assumed to be lowercase and normalised (literals → ?).
    """
    if not fingerprint or not fingerprint.strip():
        return None

    fp = fingerprint.strip().lower()

    # Priority 1 — exploitation (check before recon because sleep/benchmark
    # would partially match recon via @@, and injection payloads are distinct)
    for pattern in _EXPLOITATION_PATTERNS:
        if pattern in fp:
            return "exploitation"

    # Priority 2 — exfiltration
    for pattern in _EXFILTRATION_PATTERNS:
        if pattern in fp:
            return "exfiltration"

    # Priority 3 — recon (system variable reads)
    for pattern in _RECON_PATTERNS:
        if fp.startswith(pattern) or pattern in fp:
            return "recon"

    # Priority 4 — privilege discovery
    for pattern in _PRIVILEGE_PATTERNS:
        if pattern in fp:
            return "privilege_discovery"

    # Priority 5 — enumeration (schema-level)
    for pattern in _ENUMERATION_PATTERNS:
        if pattern in fp:
            return "enumeration"

    # Priority 6 — data_discovery
    # Matches SELECT queries against non-system tables.
    # Also triggers for any access to trap/honeytoken tables.
    phase = _classify_data_discovery(fp)
    if phase:
        return phase

    return None


def _classify_data_discovery(fp: str) -> str | None:
    """
    Classify as data_discovery if:
    - Query starts with a data-reading SELECT pattern, AND
    - Does not target a known system table.

    Also returns data_discovery for any access to trap tables regardless
    of query type (INSERT/UPDATE/DELETE against trap tables is still notable).
    """
    # Check trap table access first (highest priority within data_discovery)
    for trap in TRAP_TABLES:
        if trap in fp:
            return "data_discovery"

    # Ordinary application SELECTs are intentionally not tagged here.
    # Data discovery should come from explicit trap table access, high-risk
    # table lists, or MITRE/session context rather than every SELECT.
    return None


def is_trap_table_access(fingerprint: str) -> bool:
    """Returns True if the query targets a honeytoken/trap table."""
    if not fingerprint:
        return False
    fp = fingerprint.strip().lower()
    return any(trap in fp for trap in TRAP_TABLES)


# ── Backward-compatibility wrapper ────────────────────────────────────────────
# redpanda_consumer.py imports `classify_phase` as a plain function.
# This wrapper delegates to the module-level classify() so both APIs work.

def is_recon_probe(fingerprint: str) -> bool:
    """Return True for low-cost database/system reconnaissance probes."""
    if not fingerprint:
        return False
    fp = fingerprint.lower().strip().rstrip(";")
    return fp.startswith("select @@") or fp.startswith("show ")


def classify_phase(query_normalized: str, username: str = "",
                   database: str = "", table: str = "") -> str | None:
    """
    Backward-compatible function wrapper around classify().
    Returns a phase string or None for ordinary application queries.
    """
    return classify(query_normalized)
