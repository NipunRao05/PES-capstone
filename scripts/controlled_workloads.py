#!/usr/bin/env python3
"""Deterministic synthetic workload plans for local honeypot calibration.

This module generates plans only. It never opens a network connection or
executes SQL. A separate future runner must enforce each query's execution_policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

WORKLOAD_VERSION = "controlled-workload-v1"
DEFAULT_SEED = 20260824
MAX_SESSION_COUNT = 10_000
REQUIRED_PROFILES = (
    "BENIGN",
    "CATALOG_RECON",
    "USER_ENUMERATION",
    "BACKUP_SEARCH",
    "CREDENTIAL_SEARCH",
    "SENSITIVE_DATA_SEARCH",
    "PRIVILEGE_PROBING",
    "DESTRUCTIVE_INTENT",
    "MIXED_MULTI_STAGE",
)
PROTOCOLS = ("mysql", "postgres")

_DATABASES = (
    "sim_northstar_hr",
    "sim_blueharbor_ops",
    "sim_cedar_finance",
    "sim_orchid_logistics",
    "sim_summit_research",
)
_USERS = (
    "sim_guest",
    "sim_reporter",
    "sim_app_reader",
    "sim_audit_viewer",
    "sim_support_user",
)
_ROLES = ("sim_analyst", "sim_auditor", "sim_operator", "sim_backup_reader")
_BACKUP_TABLES = (
    "api_keys_backup",
    "backup_passwords",
    "credit_cards_archive",
    "sim_snapshot_history",
    "sim_migration_archive",
)
_CREDENTIAL_TABLES = (
    "prod_credentials",
    "admin_tokens",
    "internal_api_keys",
    "aws_credentials",
)
_SENSITIVE_TABLES = (
    "employees",
    "payroll",
    "salary_executives",
    "transactions",
    "payment_tokens",
)
_BANNED_SQL = (
    re.compile(r"https?://", re.I),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\bcopy\b.*\bprogram\b", re.I),
    re.compile(r"\b(?:load_file|into\s+outfile|xp_cmdshell|sys_exec|dblink)\b", re.I),
    re.compile(r"\bcreate\s+extension\b", re.I),
    re.compile(r"\\!"),
)
_DESTRUCTIVE_SQL = re.compile(r"^\s*(?:drop|truncate|delete|alter)\b", re.I)
_SAFE_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")


@dataclass(frozen=True)
class QueryTemplate:
    statement: str
    family: str
    execution_policy: str = "DECOY_ONLY"


@dataclass(frozen=True)
class ProfileSpec:
    profile: str
    min_depth: int
    expected_signals: tuple[str, ...]
    mysql: tuple[QueryTemplate, ...]
    postgres: tuple[QueryTemplate, ...]

    def templates(self, protocol: str) -> tuple[QueryTemplate, ...]:
        return self.mysql if protocol == "mysql" else self.postgres


def _q(statement: str, family: str, policy: str = "DECOY_ONLY") -> QueryTemplate:
    return QueryTemplate(statement, family, policy)


_PROFILES = {
    "BENIGN": ProfileSpec(
        "BENIGN", 2, ("benign",),
        (
            _q("SELECT 1;", "benign"),
            _q("SELECT DATABASE();", "benign"),
            _q("SELECT CURRENT_USER();", "benign"),
            _q("SELECT @@version_comment;", "benign"),
            _q("SELECT NOW();", "benign"),
        ),
        (
            _q("SELECT 1;", "benign"),
            _q("SELECT current_database();", "benign"),
            _q("SELECT current_user;", "benign"),
            _q("SELECT version();", "benign"),
            _q("SELECT now();", "benign"),
        ),
    ),
    "CATALOG_RECON": ProfileSpec(
        "CATALOG_RECON", 2, ("catalog", "metadata"),
        (
            _q("SHOW DATABASES;", "catalog"),
            _q("SHOW TABLES;", "catalog"),
            _q("SHOW FULL TABLES;", "metadata"),
            _q("SELECT table_name FROM information_schema.tables LIMIT 20;", "catalog"),
            _q("SELECT column_name FROM information_schema.columns LIMIT 20;", "metadata"),
        ),
        (
            _q("SELECT datname FROM pg_catalog.pg_database;", "catalog"),
            _q("SELECT tablename FROM pg_catalog.pg_tables LIMIT 20;", "catalog"),
            _q("SELECT table_name FROM information_schema.tables LIMIT 20;", "catalog"),
            _q("SELECT column_name FROM information_schema.columns LIMIT 20;", "metadata"),
            _q("SELECT current_schema();", "metadata"),
        ),
    ),
    "USER_ENUMERATION": ProfileSpec(
        "USER_ENUMERATION", 2, ("role_enumeration",),
        (
            _q("SELECT user, host FROM mysql.user;", "role_enumeration"),
            _q("SHOW GRANTS;", "role_enumeration"),
            _q("SELECT CURRENT_USER();", "role_enumeration"),
            _q("SELECT grantee FROM information_schema.user_privileges;", "role_enumeration"),
        ),
        (
            _q("SELECT rolname FROM pg_catalog.pg_roles;", "role_enumeration"),
            _q("SELECT usename FROM pg_catalog.pg_user;", "role_enumeration"),
            _q("SELECT current_user;", "role_enumeration"),
            _q("SELECT grantee FROM information_schema.role_table_grants;", "role_enumeration"),
        ),
    ),
    "BACKUP_SEARCH": ProfileSpec(
        "BACKUP_SEARCH", 2, ("backup_interest",),
        (
            _q("SHOW TABLES LIKE '%backup%';", "backup_interest"),
            _q("SELECT * FROM {backup_table} LIMIT 10;", "backup_interest"),
            _q("SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%archive%';", "backup_interest"),
            _q("SELECT * FROM {backup_table} ORDER BY 1 DESC LIMIT 5;", "backup_interest"),
            _q("SHOW CREATE TABLE {backup_table};", "backup_interest"),
        ),
        (
            _q("SELECT tablename FROM pg_catalog.pg_tables WHERE tablename LIKE '%backup%';", "backup_interest"),
            _q("SELECT * FROM {backup_table} LIMIT 10;", "backup_interest"),
            _q("SELECT table_name FROM information_schema.tables WHERE table_name LIKE '%archive%';", "backup_interest"),
            _q("SELECT * FROM {backup_table} ORDER BY 1 DESC LIMIT 5;", "backup_interest"),
            _q("SELECT column_name FROM information_schema.columns WHERE table_name = '{backup_table}';", "backup_interest"),
        ),
    ),
    "CREDENTIAL_SEARCH": ProfileSpec(
        "CREDENTIAL_SEARCH", 2, ("credential_interest", "trap_interest"),
        (
            _q("SELECT username FROM {credential_table} LIMIT 10;", "credential_interest"),
            _q("SELECT token_name FROM {credential_table} LIMIT 10;", "trap_interest"),
            _q("SELECT column_name FROM information_schema.columns WHERE column_name LIKE '%password%';", "credential_interest"),
            _q("SELECT * FROM {credential_table} ORDER BY 1 DESC LIMIT 5;", "trap_interest"),
            _q("SHOW COLUMNS FROM {credential_table};", "credential_interest"),
        ),
        (
            _q("SELECT username FROM {credential_table} LIMIT 10;", "credential_interest"),
            _q("SELECT token_name FROM {credential_table} LIMIT 10;", "trap_interest"),
            _q("SELECT column_name FROM information_schema.columns WHERE column_name LIKE '%password%';", "credential_interest"),
            _q("SELECT * FROM {credential_table} ORDER BY 1 DESC LIMIT 5;", "trap_interest"),
            _q("SELECT column_name FROM information_schema.columns WHERE table_name = '{credential_table}';", "credential_interest"),
        ),
    ),
    "SENSITIVE_DATA_SEARCH": ProfileSpec(
        "SENSITIVE_DATA_SEARCH", 2, ("sensitive_data",),
        (
            _q("SELECT * FROM {sensitive_table} LIMIT 20;", "sensitive_data"),
            _q("SELECT COUNT(*) FROM {sensitive_table};", "sensitive_data"),
            _q("SELECT * FROM {sensitive_table} ORDER BY 1 DESC LIMIT 10;", "sensitive_data"),
            _q("SHOW COLUMNS FROM {sensitive_table};", "sensitive_data"),
            _q("SELECT table_name FROM information_schema.tables WHERE table_name = '{sensitive_table}';", "sensitive_data"),
        ),
        (
            _q("SELECT * FROM {sensitive_table} LIMIT 20;", "sensitive_data"),
            _q("SELECT COUNT(*) FROM {sensitive_table};", "sensitive_data"),
            _q("SELECT * FROM {sensitive_table} ORDER BY 1 DESC LIMIT 10;", "sensitive_data"),
            _q("SELECT column_name FROM information_schema.columns WHERE table_name = '{sensitive_table}';", "sensitive_data"),
            _q("SELECT table_name FROM information_schema.tables WHERE table_name = '{sensitive_table}';", "sensitive_data"),
        ),
    ),
    "PRIVILEGE_PROBING": ProfileSpec(
        "PRIVILEGE_PROBING", 2, ("privilege_attempt", "role_enumeration"),
        (
            _q("SHOW GRANTS;", "role_enumeration"),
            _q("SELECT grantee FROM information_schema.user_privileges;", "role_enumeration"),
            _q("SET ROLE {role};", "privilege_attempt", "SIMULATE_ONLY"),
            _q("GRANT SELECT ON {managed_table} TO {user};", "privilege_attempt", "SIMULATE_ONLY"),
            _q("REVOKE SELECT ON {managed_table} FROM {user};", "privilege_attempt", "SIMULATE_ONLY"),
        ),
        (
            _q("SELECT rolname FROM pg_catalog.pg_roles;", "role_enumeration"),
            _q("SELECT grantee FROM information_schema.role_table_grants;", "role_enumeration"),
            _q("SET ROLE {role};", "privilege_attempt", "SIMULATE_ONLY"),
            _q("GRANT SELECT ON {managed_table} TO {user};", "privilege_attempt", "SIMULATE_ONLY"),
            _q("REVOKE SELECT ON {managed_table} FROM {user};", "privilege_attempt", "SIMULATE_ONLY"),
        ),
    ),
    "DESTRUCTIVE_INTENT": ProfileSpec(
        "DESTRUCTIVE_INTENT", 2, ("destructive",),
        (
            _q("DROP TABLE {managed_table};", "destructive", "SIMULATE_ONLY"),
            _q("TRUNCATE TABLE {managed_table};", "destructive", "SIMULATE_ONLY"),
            _q("DELETE FROM {managed_table};", "destructive", "SIMULATE_ONLY"),
            _q("ALTER TABLE {managed_table} DROP COLUMN sim_note;", "destructive", "SIMULATE_ONLY"),
        ),
        (
            _q("DROP TABLE {managed_table};", "destructive", "SIMULATE_ONLY"),
            _q("TRUNCATE TABLE {managed_table};", "destructive", "SIMULATE_ONLY"),
            _q("DELETE FROM {managed_table};", "destructive", "SIMULATE_ONLY"),
            _q("ALTER TABLE {managed_table} DROP COLUMN sim_note;", "destructive", "SIMULATE_ONLY"),
        ),
    ),
    "MIXED_MULTI_STAGE": ProfileSpec(
        "MIXED_MULTI_STAGE", 5,
        ("catalog", "credential_interest", "sensitive_data", "destructive"),
        (
            _q("SHOW DATABASES;", "catalog"),
            _q("SELECT user, host FROM mysql.user;", "role_enumeration"),
            _q("SELECT * FROM {backup_table} LIMIT 10;", "backup_interest"),
            _q("SELECT * FROM {credential_table} LIMIT 10;", "credential_interest"),
            _q("SELECT * FROM {sensitive_table} LIMIT 20;", "sensitive_data"),
            _q("SET ROLE {role};", "privilege_attempt", "SIMULATE_ONLY"),
            _q("DROP TABLE {managed_table};", "destructive", "SIMULATE_ONLY"),
        ),
        (
            _q("SELECT datname FROM pg_catalog.pg_database;", "catalog"),
            _q("SELECT rolname FROM pg_catalog.pg_roles;", "role_enumeration"),
            _q("SELECT * FROM {backup_table} LIMIT 10;", "backup_interest"),
            _q("SELECT * FROM {credential_table} LIMIT 10;", "credential_interest"),
            _q("SELECT * FROM {sensitive_table} LIMIT 20;", "sensitive_data"),
            _q("SET ROLE {role};", "privilege_attempt", "SIMULATE_ONLY"),
            _q("DROP TABLE {managed_table};", "destructive", "SIMULATE_ONLY"),
        ),
    ),
}


def _session_seed(seed: int, index: int, profile: str) -> int:
    digest = hashlib.sha256(f"{seed}:{index}:{profile}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big")


def _timing(rng: random.Random, count: int, mode: str) -> tuple[list[int], int]:
    ranges = {
        "burst": (5, 30, 20, 120),
        "paced": (120, 450, 500, 1800),
        "jittered": (25, 800, 100, 1200),
    }
    low, high, hold_low, hold_high = ranges[mode]
    delays = [rng.randint(low, high) for _ in range(count)]
    return delays, rng.randint(hold_low, hold_high)


def generate_session(index: int, seed: int = DEFAULT_SEED) -> dict:
    if index < 0:
        raise ValueError("index must be nonnegative")
    profile = REQUIRED_PROFILES[index % len(REQUIRED_PROFILES)]
    protocol = PROTOCOLS[(index // len(REQUIRED_PROFILES)) % len(PROTOCOLS)]
    derived_seed = _session_seed(seed, index, profile)
    rng = random.Random(derived_seed)
    spec = _PROFILES[profile]
    database = rng.choice(_DATABASES)
    username = rng.choice(_USERS)
    role = rng.choice(_ROLES)
    backup_table = rng.choice(_BACKUP_TABLES)
    credential_table = rng.choice(_CREDENTIAL_TABLES)
    sensitive_table = rng.choice(_SENSITIVE_TABLES)
    managed_table = f"sim_managed_{rng.randrange(10_000):04d}"
    substitutions = {
        "database": database,
        "user": username,
        "role": role,
        "backup_table": backup_table,
        "credential_table": credential_table,
        "sensitive_table": sensitive_table,
        "managed_table": managed_table,
    }
    templates = list(spec.templates(protocol))
    mandatory = []
    for family in spec.expected_signals:
        candidates = [item for item in templates if item.family == family]
        if not candidates:
            raise ValueError(f"profile {profile} lacks required family {family}")
        mandatory.append(rng.choice(candidates))
    remaining = [item for item in templates if item not in mandatory]
    rng.shuffle(remaining)
    minimum_depth = max(spec.min_depth, len(mandatory))
    depth = rng.randint(minimum_depth, len(templates))
    templates = mandatory + remaining[:depth - len(mandatory)]
    rng.shuffle(templates)
    timing_mode = ("burst", "paced", "jittered")[(index // 3) % 3]
    delays, hold_open_ms = _timing(rng, depth, timing_mode)
    offset = 0
    queries = []
    for ordinal, (template, delay_ms) in enumerate(zip(templates, delays), start=1):
        offset += delay_ms
        statement = template.statement.format(**substitutions)
        queries.append({
            "ordinal": ordinal,
            "scheduled_offset_ms": offset,
            "delay_ms": delay_ms,
            "statement": statement,
            "expected_family": template.family,
            "execution_policy": template.execution_policy,
        })
    identity = hashlib.sha256(
        f"{WORKLOAD_VERSION}:{seed}:{index}:{derived_seed}".encode("ascii")
    ).hexdigest()[:16]
    session = {
        "workload_version": WORKLOAD_VERSION,
        "session_id": f"cw-{index:06d}-{identity}",
        "profile": profile,
        "seed": seed,
        "derived_seed": derived_seed,
        "synthetic": True,
        "network_scope": "LOCAL_DECOY_ONLY",
        "protocol": protocol,
        "database": database,
        "username": username,
        "timing_mode": timing_mode,
        "attack_depth": depth,
        "hold_open_ms": hold_open_ms,
        "planned_duration_ms": offset + hold_open_ms,
        "assets": {
            "backup_table": backup_table,
            "credential_table": credential_table,
            "sensitive_table": sensitive_table,
            "managed_table": managed_table,
            "role": role,
        },
        "expected_signals": list(spec.expected_signals),
        "queries": queries,
    }
    validate_session(session)
    return session


def iter_sessions(count: int, seed: int = DEFAULT_SEED) -> Iterator[dict]:
    if isinstance(count, bool) or count < 1 or count > MAX_SESSION_COUNT:
        raise ValueError(f"count must be between 1 and {MAX_SESSION_COUNT}")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    for index in range(count):
        yield generate_session(index, seed)


def validate_session(session: dict) -> None:
    if not isinstance(session, dict):
        raise ValueError("session must be an object")
    if session.get("workload_version") != WORKLOAD_VERSION:
        raise ValueError("unexpected workload version")
    if session.get("synthetic") is not True:
        raise ValueError("controlled sessions must be explicitly synthetic")
    if session.get("network_scope") != "LOCAL_DECOY_ONLY":
        raise ValueError("only local decoy scope is allowed")
    if session.get("profile") not in REQUIRED_PROFILES:
        raise ValueError("unknown workload profile")
    if session.get("protocol") not in PROTOCOLS:
        raise ValueError("unsupported protocol")
    if not _SAFE_IDENTIFIER.fullmatch(str(session.get("database") or "")):
        raise ValueError("unsafe database identifier")
    if not str(session["database"]).startswith("sim_"):
        raise ValueError("database must use the synthetic namespace")
    if not _SAFE_IDENTIFIER.fullmatch(str(session.get("username") or "")):
        raise ValueError("unsafe username")
    if not str(session["username"]).startswith("sim_"):
        raise ValueError("username must use the synthetic namespace")
    queries = session.get("queries")
    if not isinstance(queries, list) or len(queries) != session.get("attack_depth"):
        raise ValueError("attack depth must match the query plan")
    offsets = []
    for query in queries:
        if not isinstance(query, dict):
            raise ValueError("query plan entries must be objects")
        statement = str(query.get("statement") or "")
        policy = query.get("execution_policy")
        if not statement or len(statement) > 4096 or statement.count(";") != 1 or not statement.endswith(";"):
            raise ValueError("each query must contain one bounded SQL statement")
        if policy not in {"DECOY_ONLY", "SIMULATE_ONLY"}:
            raise ValueError("unknown execution policy")
        if _DESTRUCTIVE_SQL.search(statement) and policy != "SIMULATE_ONLY":
            raise ValueError("destructive intent must be simulate-only")
        if any(pattern.search(statement) for pattern in _BANNED_SQL):
            raise ValueError("query contains forbidden external or command capability")
        delay = query.get("delay_ms")
        offset = query.get("scheduled_offset_ms")
        if isinstance(delay, bool) or not isinstance(delay, int) or not 0 <= delay <= 2_000:
            raise ValueError("query delay is outside the bounded range")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("query offset is invalid")
        offsets.append(offset)
    if offsets != sorted(offsets) or len(set(offsets)) != len(offsets):
        raise ValueError("query offsets must be strictly increasing")
    duration = session.get("planned_duration_ms")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, int)
        or duration != offsets[-1] + session.get("hold_open_ms", -1)
    ):
        raise ValueError("planned duration is inconsistent")


def canonical_json(session: dict) -> str:
    validate_session(session)
    return json.dumps(session, sort_keys=True, separators=(",", ":"), allow_nan=False)


def plan_hash(sessions: Iterable[dict]) -> str:
    digest = hashlib.sha256()
    for session in sessions:
        digest.update(canonical_json(session).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def summarize(sessions: list[dict]) -> dict:
    if not sessions:
        raise ValueError("at least one session is required")
    profiles = Counter(item["profile"] for item in sessions)
    protocols = Counter(item["protocol"] for item in sessions)
    depths = [item["attack_depth"] for item in sessions]
    durations = [item["planned_duration_ms"] for item in sessions]
    order_signatures = {
        tuple(query["expected_family"] for query in item["queries"])
        for item in sessions
    }
    return {
        "workload_version": WORKLOAD_VERSION,
        "session_count": len(sessions),
        "plan_sha256": plan_hash(sessions),
        "profiles": dict(sorted(profiles.items())),
        "protocols": dict(sorted(protocols.items())),
        "variation": {
            "query_order_signatures": len(order_signatures),
            "databases": len({item["database"] for item in sessions}),
            "table_asset_sets": len({
                tuple(sorted((key, value) for key, value in item["assets"].items() if key.endswith("table")))
                for item in sessions
            }),
            "usernames": len({item["username"] for item in sessions}),
            "timing_modes": len({item["timing_mode"] for item in sessions}),
            "attack_depth_min": min(depths),
            "attack_depth_max": max(depths),
            "duration_ms_min": min(durations),
            "duration_ms_max": max(durations),
        },
        "synthetic_only": all(item["synthetic"] is True for item in sessions),
        "local_decoy_only": all(
            item["network_scope"] == "LOCAL_DECOY_ONLY" for item in sessions
        ),
        "execution_performed": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "generate"):
        command = subparsers.add_parser(name)
        command.add_argument("--count", type=int, default=1_000)
        command.add_argument("--seed", type=int, default=DEFAULT_SEED)
        if name == "generate":
            command.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    sessions = list(iter_sessions(args.count, args.seed))
    summary = summarize(sessions)
    replay_hash = plan_hash(iter_sessions(args.count, args.seed))
    summary["deterministic_replay"] = replay_hash == summary["plan_sha256"]
    if not summary["deterministic_replay"]:
        raise RuntimeError("same-seed generation was not deterministic")
    if args.command == "generate":
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            for session in sessions:
                handle.write(canonical_json(session) + "\n")
        summary["output"] = str(output)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
