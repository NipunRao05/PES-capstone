"""Deterministic Phase 17 candidate-strategy validation pipeline.

VALIDATED means only that Phase 17 checks passed. This module cannot modify the
strategy registry, activate policy, deploy assets, execute SQL, or start Phase 18.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from typing import Any, Callable

try:
    from .review import REVIEW_SCHEMA_VERSION, validate_proposal
except ImportError:  # Direct script execution in the documented local container.
    from review import REVIEW_SCHEMA_VERSION, validate_proposal

VALIDATOR_VERSION = "candidate-validation-v1"
CANDIDATE_SCHEMA_VERSION = "candidate-strategy-v1"

_CANDIDATE_FIELDS = {
    "candidate_schema_version", "strategy_id", "name", "description",
    "supported_protocols", "required_state", "forbidden_state",
    "activation_conditions", "compatible_personas", "schema_assets",
    "trap_assets", "risk_level", "resource_cost", "validation_version",
}
_INPUT_FIELDS = {
    "proposal", "review", "candidate_strategy", "database_assets",
    "state_contract", "trap_definitions", "resource_limits",
}
_REVIEW_FIELDS = {
    "review_schema_version", "review_id", "proposal_id", "proposal_version",
    "proposal_sha256", "reviewer", "timestamp", "decision", "prior_status",
    "resulting_status", "reason", "modifications", "requested_evidence",
    "can_proceed_to_validation", "next_phase", "authority",
    "validation_handoff", "audit",
}
_APPROVED_REVIEW_AUTHORITY = {
    "deployable": False,
    "strategy_registry_approved": False,
    "requires_phase_17_validation": True,
    "validation_started": False,
    "registry_mutation": False,
    "policy_mutation": False,
    "strategy_activation": False,
    "asset_deployment": False,
}
_PROTOCOLS = {"mysql", "postgres"}
_RISK = {"low", "medium", "high", "critical"}
_COST = {"low", "medium", "high"}
_TYPES = {
    "mysql": {
        "INT", "INTEGER", "BIGINT", "VARCHAR", "TEXT", "DECIMAL", "BOOLEAN",
        "DATETIME", "TIMESTAMP", "JSON", "BLOB",
    },
    "postgres": {
        "INT", "INTEGER", "BIGINT", "VARCHAR", "TEXT", "NUMERIC", "DECIMAL",
        "BOOLEAN", "TIMESTAMP", "JSON", "JSONB", "UUID", "BYTEA",
    },
}
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SAFE_ASSET = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_STRATEGY_ID = re.compile(r"^D[0-9]+$")
_REVIEW_ID = re.compile(r"^RV-[0-9a-f]{24}$")
_PROPOSAL_ID = re.compile(r"^P-[0-9a-f]{24}$")
_CREATE_TABLE = re.compile(
    r"^\s*CREATE\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*;?\s*$",
    re.IGNORECASE | re.DOTALL,
)
_URL = re.compile(r"(?i)\b(?:https?|ftp|s3|gs|mysql|postgres(?:ql)?)://")
_EXTERNAL_DOMAIN = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|cloud|amazonaws\.com)\b"
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,255}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,255}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
)
_FORBIDDEN_SQL = (
    re.compile(r"(?i)\b(?:COPY|LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE|DBLINK)\b"),
    re.compile(r"(?i)\b(?:DROP|ALTER|TRUNCATE|GRANT|REVOKE|CALL|EXECUTE)\b"),
    re.compile(r"(?i)\\[!iwo]"),
    _URL,
)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("validation input must contain finite JSON values") from exc


def _bounded_text(value: Any, field: str, limit: int = 1024) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value.strip()
    if not text or len(text) > limit:
        raise ValueError(f"{field} is required and must be <= {limit} characters")
    return text


def _string_list(value: Any, field: str, *, minimum: int = 0, maximum: int = 50) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} has an invalid item count")
    result: list[str] = []
    for item in value:
        text = _bounded_text(item, field, 256)
        if text in result:
            raise ValueError(f"{field} contains duplicates")
        result.append(text)
    return result


def _walk(value: Any, path: str = "input") -> None:
    if isinstance(value, dict):
        if len(value) > 100:
            raise ValueError(f"{path} contains too many fields")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError(f"{path} contains an invalid field name")
            _walk(item, f"{path}.{key}")
    elif isinstance(value, list):
        if len(value) > 250:
            raise ValueError(f"{path} exceeds the bounded list size")
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]")
    elif isinstance(value, str) and len(value) > 16_384:
        raise ValueError(f"{path} exceeds the bounded string size")
    elif isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{path} must be finite")


def _check(stage: int, name: str, status: str, evidence: list[str], *, required: bool = True) -> dict:
    return {
        "stage": stage,
        "name": name,
        "status": status,
        "required": required,
        "evidence": sorted({str(item)[:512] for item in evidence}),
    }


def _split_sql_items(body: str) -> list[str]:
    items: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(body):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("SQL contains unbalanced parentheses")
        elif character == "," and depth == 0:
            items.append(body[start:index].strip())
            start = index + 1
    if depth != 0:
        raise ValueError("SQL contains unbalanced parentheses")
    items.append(body[start:].strip())
    if any(not item for item in items):
        raise ValueError("SQL contains an empty table item")
    return items


def _type_base(value: str) -> str:
    return str(value or "").strip().upper().split("(", 1)[0]


def _parse_create_table(sql: str, protocol: str) -> tuple[str, list[str]]:
    if not isinstance(sql, str) or not sql.strip() or len(sql) > 16_384:
        raise ValueError("SQL must be a nonempty bounded string")
    statement = sql.strip()
    if statement.count(";") > (1 if statement.endswith(";") else 0):
        raise ValueError("SQL assets must contain exactly one statement")
    if any(pattern.search(statement) for pattern in _FORBIDDEN_SQL):
        raise ValueError("SQL contains a forbidden database, external, or client capability")
    match = _CREATE_TABLE.fullmatch(statement)
    if not match:
        raise ValueError("only bounded CREATE TABLE candidate SQL is supported")
    table = match.group(1)
    columns: list[str] = []
    for item in _split_sql_items(match.group(2)):
        parts = item.split()
        if not parts:
            raise ValueError("SQL table item is empty")
        if parts[0].upper() in {"PRIMARY", "FOREIGN", "CONSTRAINT", "UNIQUE", "INDEX", "KEY"}:
            continue
        column = parts[0].strip('`"')
        if not _SAFE_IDENTIFIER.fullmatch(column) or len(parts) < 2:
            raise ValueError("SQL column definition is invalid")
        type_name = _type_base(parts[1])
        if type_name not in _TYPES[protocol]:
            raise ValueError(f"SQL type {type_name or 'UNKNOWN'} is unsupported for {protocol}")
        if column.lower() in {item.lower() for item in columns}:
            raise ValueError("SQL contains duplicate columns")
        columns.append(column)
    if not columns:
        raise ValueError("SQL table must define at least one column")
    return table, columns


def _network_findings(value: Any, path: str = "candidate") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"callback", "webhook", "external_host", "endpoint", "connection_string"}:
                findings.append(f"forbidden network field at {path}.{key}")
            findings.extend(_network_findings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_network_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        if _URL.search(value) or _EXTERNAL_DOMAIN.search(value):
            findings.append(f"external endpoint reference at {path}")
        for address in _IPV4.findall(value):
            if not address.startswith(("127.", "10.", "192.168.")):
                findings.append(f"external IP reference at {path}")
    return findings


def _secret_findings(value: Any, path: str = "candidate") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"real_secret", "production_credential", "customer_pii"}:
                findings.append(f"prohibited sensitive field at {path}.{key}")
            findings.extend(_secret_findings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_secret_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str) and any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        findings.append(f"credential or PII-like value at {path}")
    return findings


def candidate_safety_findings(value: Any) -> dict[str, list[str]]:
    """Expose the Phase 17 deterministic secret/PII and egress scanners read-only."""
    _walk(value, "candidate")
    return {
        "sensitive": sorted(set(_secret_findings(value))),
        "network": sorted(set(_network_findings(value))),
    }


class CandidateValidationPipeline:
    """Run the ordered fail-closed Phase 17 validation stages."""

    def validate(self, validation_input: dict, registry: dict) -> dict:
        digest = hashlib.sha256(_canonical((validation_input, registry, VALIDATOR_VERSION))).hexdigest()
        candidate = validation_input.get("candidate_strategy", {}) if isinstance(validation_input, dict) else {}
        candidate_id = str(candidate.get("strategy_id") or "UNKNOWN")[:64] if isinstance(candidate, dict) else "UNKNOWN"
        proposal_id = ""
        review_id = ""
        checks: list[dict] = []
        warnings: list[str] = []

        try:
            if not isinstance(validation_input, dict) or set(validation_input) != _INPUT_FIELDS:
                raise ValueError("complete candidate validation input is required")
            if len(_canonical(validation_input)) > 512_000:
                raise ValueError("candidate validation input exceeds 512000 bytes")
            _walk(validation_input)
            proposal = validate_proposal(validation_input["proposal"])
            review = validation_input["review"]
            if not isinstance(review, dict) or set(review) != _REVIEW_FIELDS:
                raise ValueError("complete Phase 16 review evidence is required")
            proposal_id = proposal["proposal_id"]
            review_id = str(review.get("review_id") or "")
            proposal_sha = hashlib.sha256(_canonical(proposal)).hexdigest()
            if (
                review.get("review_schema_version") != REVIEW_SCHEMA_VERSION
                or not _REVIEW_ID.fullmatch(review_id)
                or not _PROPOSAL_ID.fullmatch(str(review.get("proposal_id") or ""))
                or review.get("proposal_id") != proposal_id
                or review.get("proposal_sha256") != proposal_sha
                or review.get("proposal_version") != 1
                or not str(review.get("reviewer") or "").strip()
                or review.get("prior_status") != "REQUIRES_REVIEW"
                or review.get("decision") != "APPROVE"
                or review.get("resulting_status") != "APPROVED_FOR_VALIDATION"
                or review.get("can_proceed_to_validation") is not True
                or review.get("next_phase") != "PHASE_17"
                or review.get("authority") != _APPROVED_REVIEW_AUTHORITY
                or review.get("modifications") != []
                or review.get("requested_evidence") != []
            ):
                raise ValueError("review is not an intact APPROVED_FOR_VALIDATION record")
            handoff = review.get("validation_handoff")
            audit = review.get("audit")
            stable_input = {
                "review_schema_version": REVIEW_SCHEMA_VERSION,
                "proposal_sha256": proposal_sha,
                "proposal_id": proposal_id,
                "proposal_version": 1,
                "reviewer": review["reviewer"],
                "decision": "APPROVE",
                "reason": review["reason"],
                "modifications": [],
                "requested_evidence": [],
            }
            stable_digest = hashlib.sha256(_canonical(stable_input)).hexdigest()
            if (
                review_id != "RV-" + stable_digest[:24]
                or not isinstance(handoff, dict)
                or handoff != {
                    "eligible": True,
                    "candidate_id": "VC-" + stable_digest[24:48],
                    "phase": "PHASE_17",
                    "validation_started": False,
                }
                or not isinstance(audit, dict)
                or audit.get("stable_review_input_sha256") != stable_digest
                or audit.get("original_proposal_preserved") is not True
            ):
                raise ValueError("review identity, handoff, or audit linkage is forged")
            checks.append(_check(1, "proposal_review_integrity", "PASS", [
                f"proposal_id={proposal_id}", f"review_id={review_id}",
                f"reviewer={review['reviewer']}", "status=APPROVED_FOR_VALIDATION",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(1, "proposal_review_integrity", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            candidate = validation_input["candidate_strategy"]
            if not isinstance(candidate, dict) or set(candidate) != _CANDIDATE_FIELDS:
                raise ValueError("candidate strategy metadata is incomplete or contains unknown fields")
            if candidate.get("candidate_schema_version") != CANDIDATE_SCHEMA_VERSION:
                raise ValueError("candidate schema version is unsupported")
            candidate_id = _bounded_text(candidate.get("strategy_id"), "strategy_id", 32)
            if not _STRATEGY_ID.fullmatch(candidate_id):
                raise ValueError("candidate strategy ID must follow the registry D<number> convention")
            name = _bounded_text(candidate.get("name"), "name", 128)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", name):
                raise ValueError("candidate name must be an uppercase registry-compatible identifier")
            _bounded_text(candidate.get("description"), "description", 2048)
            _bounded_text(candidate.get("validation_version"), "validation_version", 128)
            protocols = _string_list(candidate.get("supported_protocols"), "supported_protocols", minimum=1)
            if not set(protocols) <= _PROTOCOLS:
                raise ValueError("candidate declares unsupported protocols")
            required_state = _string_list(candidate.get("required_state"), "required_state")
            forbidden_state = _string_list(candidate.get("forbidden_state"), "forbidden_state")
            if set(required_state) & set(forbidden_state):
                raise ValueError("candidate requires and forbids the same state")
            _string_list(candidate.get("activation_conditions"), "activation_conditions", minimum=1)
            _string_list(candidate.get("compatible_personas"), "compatible_personas", minimum=1)
            schema_assets = _string_list(candidate.get("schema_assets"), "schema_assets")
            trap_assets = _string_list(candidate.get("trap_assets"), "trap_assets")
            if any(not _SAFE_ASSET.fullmatch(asset) for asset in schema_assets + trap_assets):
                raise ValueError("candidate contains an unsafe asset identifier")
            if candidate.get("risk_level") not in _RISK or candidate.get("resource_cost") not in _COST:
                raise ValueError("candidate risk or resource class is invalid")
            checks.append(_check(2, "strategy_schema_validation", "PASS", [
                f"strategy_id={candidate_id}", f"protocols={','.join(sorted(protocols))}",
                f"risk={candidate['risk_level']}", f"cost={candidate['resource_cost']}",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(2, "strategy_schema_validation", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            if not isinstance(registry, dict) or registry.get("degraded") is not False:
                raise ValueError("a non-degraded read-only registry snapshot is required")
            registry_version = _bounded_text(registry.get("registry_version"), "registry_version", 128)
            strategies = registry.get("strategies")
            if not isinstance(strategies, list) or not strategies:
                raise ValueError("registry strategies are required")
            existing_ids = {str(item.get("strategy_id") or "") for item in strategies if isinstance(item, dict)}
            existing_names = {str(item.get("name") or "").strip().casefold() for item in strategies if isinstance(item, dict)}
            if candidate_id in existing_ids or candidate_id in {f"D{index}" for index in range(8)}:
                raise ValueError("candidate strategy ID collides with an existing or reserved D0-D7 identifier")
            if candidate["name"].casefold() in existing_names:
                raise ValueError("candidate strategy name collides with the registry")
            checks.append(_check(3, "registry_collision_check", "PASS", [
                f"registry_version={registry_version}", f"existing_strategy_count={len(existing_ids)}",
                "registry_access=read_only",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(3, "registry_collision_check", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            assets = validation_input["database_assets"]
            if not isinstance(assets, list) or len(assets) > 20:
                raise ValueError("database_assets must be a list of at most 20 entries")
            parsed_assets: dict[str, dict] = {}
            for asset in assets:
                if not isinstance(asset, dict) or set(asset) != {
                    "asset_id", "protocol", "object_type", "sql", "schema", "rows"
                }:
                    raise ValueError("database asset schema is invalid")
                asset_id = _bounded_text(asset.get("asset_id"), "asset_id", 128)
                protocol = str(asset.get("protocol") or "").lower()
                if not _SAFE_ASSET.fullmatch(asset_id) or asset_id in parsed_assets:
                    raise ValueError("database asset ID is unsafe or duplicated")
                if protocol not in _PROTOCOLS or asset.get("object_type") != "table":
                    raise ValueError("database asset protocol or object type is unsupported")
                table, sql_columns = _parse_create_table(asset.get("sql"), protocol)
                schema = asset.get("schema")
                if not isinstance(schema, dict) or schema.get("table") != table:
                    raise ValueError("SQL table and structured schema do not match")
                if not isinstance(asset.get("rows"), list) or len(asset["rows"]) > 1000:
                    raise ValueError("asset rows must be a bounded list")
                parsed_assets[asset_id] = {
                    "asset": asset, "table": table, "sql_columns": sql_columns,
                }
            if set(candidate["schema_assets"]) != set(parsed_assets):
                raise ValueError("declared schema assets and supplied database assets differ")
            checks.append(_check(4, "sql_database_asset_validation", "PASS", [
                f"database_asset_count={len(parsed_assets)}", "sql_execution=false",
                "single_create_table_only=true",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(4, "sql_database_asset_validation", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            table_index: dict[str, dict] = {}
            for asset_id, parsed in parsed_assets.items():
                schema = parsed["asset"]["schema"]
                if set(schema) != {"table", "columns", "primary_key", "foreign_keys", "indexes"}:
                    raise ValueError("structured table schema contains unknown or missing fields")
                columns = schema.get("columns")
                if not isinstance(columns, list) or not columns:
                    raise ValueError("table schema requires columns")
                column_map: dict[str, str] = {}
                for column in columns:
                    if not isinstance(column, dict) or set(column) != {"name", "type", "nullable"}:
                        raise ValueError("column schema is invalid")
                    name = str(column.get("name") or "")
                    type_name = _type_base(column.get("type"))
                    if (
                        not _SAFE_IDENTIFIER.fullmatch(name)
                        or name.lower() in column_map
                        or type_name not in _TYPES[parsed["asset"]["protocol"]]
                        or not isinstance(column.get("nullable"), bool)
                    ):
                        raise ValueError("column name, type, nullability, or uniqueness is invalid")
                    column_map[name.lower()] = type_name
                if {name.lower() for name in parsed["sql_columns"]} != set(column_map):
                    raise ValueError("SQL and structured schema columns differ")
                primary = schema.get("primary_key")
                if not isinstance(primary, list) or any(str(item).lower() not in column_map for item in primary):
                    raise ValueError("primary key references an unknown column")
                indexes = schema.get("indexes")
                if not isinstance(indexes, list):
                    raise ValueError("indexes must be a list")
                for index in indexes:
                    if not isinstance(index, dict) or set(index) != {"name", "columns"}:
                        raise ValueError("index schema is invalid")
                    if not _SAFE_IDENTIFIER.fullmatch(str(index.get("name") or "")):
                        raise ValueError("index name is invalid")
                    if not isinstance(index.get("columns"), list) or any(
                        str(item).lower() not in column_map for item in index["columns"]
                    ):
                        raise ValueError("index references an unknown column")
                table_index[asset_id] = {"columns": column_map, "schema": schema}
            for asset_id, table in table_index.items():
                foreign_keys = table["schema"].get("foreign_keys")
                if not isinstance(foreign_keys, list):
                    raise ValueError("foreign_keys must be a list")
                for foreign_key in foreign_keys:
                    if not isinstance(foreign_key, dict) or set(foreign_key) != {
                        "columns", "references_asset", "references_columns"
                    }:
                        raise ValueError("foreign key schema is invalid")
                    target = table_index.get(str(foreign_key.get("references_asset") or ""))
                    local_columns = foreign_key.get("columns")
                    remote_columns = foreign_key.get("references_columns")
                    if (
                        target is None or not isinstance(local_columns, list)
                        or not isinstance(remote_columns, list) or not local_columns
                        or len(local_columns) != len(remote_columns)
                        or any(str(item).lower() not in table["columns"] for item in local_columns)
                        or any(str(item).lower() not in target["columns"] for item in remote_columns)
                    ):
                        raise ValueError("foreign key references an invalid object or column")
            checks.append(_check(5, "schema_consistency", "PASS", [
                f"validated_table_count={len(table_index)}", "pk_fk_index_links=consistent",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(5, "schema_consistency", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        secret_findings = _secret_findings({
            "database_assets": validation_input["database_assets"],
            "trap_definitions": validation_input["trap_definitions"],
        })
        if secret_findings:
            checks.append(_check(6, "synthetic_data_safety", "FAIL", secret_findings))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)
        checks.append(_check(6, "synthetic_data_safety", "PASS", [
            "credential_and_pii_patterns=absent", "deterministic_scan=true",
        ]))

        network_findings = _network_findings(validation_input)
        if network_findings:
            checks.append(_check(7, "network_egress_safety", "FAIL", network_findings))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)
        checks.append(_check(7, "network_egress_safety", "PASS", [
            "external_endpoints=absent", "outbound_requirements=absent",
        ]))

        try:
            protocols = set(candidate["supported_protocols"])
            for asset in validation_input["database_assets"]:
                protocol = asset["protocol"]
                sql = asset["sql"]
                if protocol not in protocols:
                    raise ValueError("database asset protocol is outside candidate declarations")
                if protocol == "mysql" and re.search(r"(?i)\b(?:SERIAL|JSONB|BYTEA)\b", sql):
                    raise ValueError("PostgreSQL-only SQL is declared as MySQL")
                if protocol == "postgres" and ("`" in sql or re.search(r"(?i)\bAUTO_INCREMENT\b", sql)):
                    raise ValueError("MySQL-only SQL is declared as PostgreSQL")
            checks.append(_check(8, "protocol_compatibility", "PASS", [
                f"declared_protocols={','.join(sorted(protocols))}",
                f"database_asset_count={len(validation_input['database_assets'])}",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(8, "protocol_compatibility", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            state = validation_input["state_contract"]
            if not isinstance(state, dict) or set(state) != {
                "observed_objects", "candidate_expectations", "retroactive_mutations"
            }:
                raise ValueError("state contract is invalid")
            observed = state.get("observed_objects")
            expected = state.get("candidate_expectations")
            retroactive = state.get("retroactive_mutations")
            if not isinstance(observed, dict) or not isinstance(expected, dict) or retroactive != []:
                raise ValueError("retroactive state mutation is forbidden")
            for object_name, columns in expected.items():
                if not _SAFE_ASSET.fullmatch(str(object_name)) or not isinstance(columns, dict):
                    raise ValueError("candidate state expectation is invalid")
                observed_columns = observed.get(object_name, {})
                if observed_columns and not isinstance(observed_columns, dict):
                    raise ValueError("observed state schema is invalid")
                for column, expected_type in columns.items():
                    observed_type = observed_columns.get(column)
                    if observed_type is not None and _type_base(observed_type) != _type_base(expected_type):
                        raise ValueError(
                            f"state contradiction for {object_name}.{column}: "
                            f"observed {_type_base(observed_type)} vs candidate {_type_base(expected_type)}"
                        )
            checks.append(_check(9, "state_consistency", "PASS", [
                f"observed_object_count={len(observed)}", "retroactive_mutations=0",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(9, "state_consistency", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            traps = validation_input["trap_definitions"]
            if not isinstance(traps, list) or len(traps) > 50:
                raise ValueError("trap_definitions must be a bounded list")
            trap_ids: set[str] = set()
            for trap in traps:
                if not isinstance(trap, dict) or set(trap) != {
                    "trap_id", "asset_id", "synthetic", "evidence_event", "action",
                    "network_activity", "offensive_action",
                }:
                    raise ValueError("trap definition is invalid")
                trap_id = str(trap.get("trap_id") or "")
                if not _SAFE_ASSET.fullmatch(trap_id) or trap_id in trap_ids:
                    raise ValueError("trap ID is unsafe or duplicated")
                if (
                    trap.get("synthetic") is not True
                    or trap.get("evidence_event") != "trap_interaction"
                    or trap.get("action") != "RECORD_ONLY"
                    or trap.get("network_activity") is not False
                    or trap.get("offensive_action") is not False
                ):
                    raise ValueError("trap authority or evidence behavior is unsafe")
                trap_ids.add(trap_id)
            declared_traps = set(candidate["trap_assets"])
            defined_assets = {str(item.get("asset_id") or "") for item in traps}
            if declared_traps != defined_assets:
                raise ValueError("declared trap assets and safe trap definitions differ")
            checks.append(_check(10, "trap_safety_validation", "PASS", [
                f"trap_count={len(traps)}", "trap_action=record_only",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(10, "trap_safety_validation", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        try:
            limits = validation_input["resource_limits"]
            if not isinstance(limits, dict) or set(limits) != {
                "cost_class", "max_rows", "max_schema_objects", "background_workers",
                "container_per_query",
            }:
                raise ValueError("resource limit contract is invalid")
            if limits.get("cost_class") != candidate["resource_cost"]:
                raise ValueError("resource cost class differs from candidate metadata")
            values = (limits.get("max_rows"), limits.get("max_schema_objects"), limits.get("background_workers"))
            if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
                raise ValueError("resource limits must be integers")
            if not 0 <= limits["max_rows"] <= 10_000:
                raise ValueError("max_rows is unbounded")
            if not 0 <= limits["max_schema_objects"] <= 100:
                raise ValueError("max_schema_objects is unbounded")
            if not 0 <= limits["background_workers"] <= 2:
                raise ValueError("background_workers is unbounded")
            if limits.get("container_per_query") is not False:
                raise ValueError("container-per-query requirements are forbidden")
            if len(validation_input["database_assets"]) > limits["max_schema_objects"]:
                raise ValueError("database assets exceed declared schema-object limit")
            row_count = sum(len(item["rows"]) for item in validation_input["database_assets"])
            if row_count > limits["max_rows"]:
                raise ValueError("synthetic rows exceed declared row limit")
            checks.append(_check(11, "resource_cost_validation", "PASS", [
                f"cost_class={limits['cost_class']}", f"max_rows={limits['max_rows']}",
                f"max_schema_objects={limits['max_schema_objects']}",
                f"background_workers={limits['background_workers']}",
            ]))
        except (ValueError, KeyError, TypeError) as exc:
            checks.append(_check(11, "resource_cost_validation", "FAIL", [str(exc)]))
            return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

        if validation_input["database_assets"]:
            checks.append(_check(12, "sandbox_validation", "NOT_VALIDATED", [
                "existing sandbox API accepts captured evidence only",
                "candidate schema import is unavailable",
                "no SQL was executed",
            ]))
            warnings.append("database assets require a future isolated candidate-import validation contract")
        else:
            checks.append(_check(12, "sandbox_validation", "NOT_APPLICABLE", [
                "candidate contains no database assets", "no sandbox execution required",
            ], required=False))
        return self._result(digest, proposal_id, review_id, candidate_id, checks, warnings, registry)

    @staticmethod
    def _result(
        digest: str,
        proposal_id: str,
        review_id: str,
        candidate_id: str,
        checks: list[dict],
        warnings: list[str],
        registry: dict,
    ) -> dict:
        failed = [item for item in checks if item["status"] == "FAIL" and item["required"]]
        incomplete = [
            item for item in checks if item["status"] == "NOT_VALIDATED" and item["required"]
        ]
        status = "REJECTED" if failed else "VALIDATION_INCOMPLETE" if incomplete else "VALIDATED"
        return {
            "validation_id": "VAL-" + digest[:24],
            "proposal_id": proposal_id,
            "review_id": review_id,
            "candidate_strategy_id": candidate_id,
            "status": status,
            "validator_version": VALIDATOR_VERSION,
            "checks": checks,
            "failed_checks": [
                {"stage": item["stage"], "name": item["name"], "evidence": item["evidence"]}
                for item in failed
            ],
            "incomplete_checks": [
                {"stage": item["stage"], "name": item["name"], "evidence": item["evidence"]}
                for item in incomplete
            ],
            "warnings": sorted(set(warnings)),
            "evidence": {
                "input_sha256": digest,
                "registry_version": str(registry.get("registry_version") or "")[:128]
                if isinstance(registry, dict) else "",
                "registry_access": "READ_ONLY",
                "sql_executed": False,
                "llm_used": False,
            },
            "authority": {
                "deployable": False,
                "strategy_registry_approved": False,
                "strategy_activation": False,
                "registry_mutation": False,
                "policy_mutation": False,
                "asset_deployment": False,
                "database_mutation": False,
                "requires_future_registry_promotion": status == "VALIDATED",
            },
            "meaning": (
                "Phase 17 technical/safety validation only; never live approval or deployment."
            ),
            "next_phase_boundary": {
                "phase_18_started": False,
                "local_llm_runtime": "NOT_IMPLEMENTED",
            },
        }
