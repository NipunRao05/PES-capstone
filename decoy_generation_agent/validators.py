"""Strict deterministic validation and Phase 17 envelope construction."""

from __future__ import annotations

import copy
import json
import math
import re
from typing import Any

from learning_agent.candidate_validation import candidate_safety_findings
from learning_agent.review import validate_proposal

from .schemas import (
    ASSET_TYPES,
    OUTPUT_SCHEMA_VERSION,
    PROTOCOLS,
    REQUEST_VERSION,
    RESOURCE_COSTS,
    RISK_LEVELS,
    SQL_TYPES,
)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_STRATEGY_ID = re.compile(r"^D[0-9]+$")
_STRATEGY_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_COMPANY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{1,79}$")
_FORBIDDEN_OUTPUT = re.compile(
    r"(?i)(?:\b(?:DROP|ALTER|TRUNCATE|GRANT|REVOKE|EXECUTE|CALL)\b|"
    r"\b(?:curl|wget|powershell|cmd\.exe|docker|kubectl)\b|"
    r"<script|javascript:|\\[!iwo])"
)
_REQUEST_FIELDS = {
    "request_version", "fictional_persona", "proposal", "review",
    "strategy_requirements", "supported_protocol",
    "existing_synthetic_schema_summary", "requested_asset_types",
}
_OUTPUT_FIELDS = {
    "description", "tables", "backup_archives", "migrations", "audit_history"
}


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("input must contain finite JSON values") from exc


def _text(value: Any, field: str, limit: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    result = value.strip()
    if not result or len(result) > limit:
        raise ValueError(f"{field} is required and bounded to {limit} characters")
    return result


def _strings(value: Any, field: str, minimum: int, maximum: int) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} has an invalid item count")
    result = [_text(item, field, 256) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{field} contains duplicates")
    return result


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, 64)
    if not _IDENTIFIER.fullmatch(result):
        raise ValueError(f"{field} is not a safe identifier")
    return result


def _safe_strings(value: Any) -> None:
    findings = candidate_safety_findings(value)
    if findings["sensitive"]:
        raise ValueError("candidate contains credential or PII-like content")
    if findings["network"]:
        raise ValueError("candidate contains an external network reference")

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)
        elif isinstance(item, str) and _FORBIDDEN_OUTPUT.search(item):
            raise ValueError("candidate contains an unsafe operation or command")

    walk(value)


def validate_generation_request(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != _REQUEST_FIELDS:
        raise ValueError("complete Phase 19 generation input is required")
    if len(_canonical(value)) > 256_000:
        raise ValueError("generation input exceeds 256000 bytes")
    if value.get("request_version") != REQUEST_VERSION:
        raise ValueError("generation request version is unsupported")
    proposal = validate_proposal(value.get("proposal"))
    review = value.get("review")
    if not isinstance(review, dict):
        raise ValueError("Phase 16 review evidence is required")

    persona = value.get("fictional_persona")
    if not isinstance(persona, dict) or set(persona) != {
        "company_name", "industry", "environment_label", "fictional"
    }:
        raise ValueError("fictional persona contract is invalid")
    if persona.get("fictional") is not True:
        raise ValueError("persona must be explicitly fictional")
    company = _text(persona.get("company_name"), "company_name", 80)
    if not _COMPANY.fullmatch(company):
        raise ValueError("fictional company name contains unsupported characters")
    _text(persona.get("industry"), "industry", 80)
    _identifier(persona.get("environment_label"), "environment_label")

    requirements = value.get("strategy_requirements")
    if not isinstance(requirements, dict) or set(requirements) != {
        "strategy_id", "name", "required_state", "forbidden_state",
        "activation_conditions", "compatible_personas", "risk_level", "resource_cost",
    }:
        raise ValueError("strategy requirements contract is invalid")
    strategy_id = _text(requirements.get("strategy_id"), "strategy_id", 32)
    if not _STRATEGY_ID.fullmatch(strategy_id):
        raise ValueError("strategy_id must follow D<number>")
    name = _text(requirements.get("name"), "strategy name", 128)
    if not _STRATEGY_NAME.fullmatch(name):
        raise ValueError("strategy name is invalid")
    required_state = _strings(requirements.get("required_state"), "required_state", 1, 20)
    forbidden_state = _strings(requirements.get("forbidden_state"), "forbidden_state", 0, 20)
    if set(required_state) & set(forbidden_state):
        raise ValueError("strategy requires and forbids the same state")
    _strings(requirements.get("activation_conditions"), "activation_conditions", 1, 20)
    _strings(requirements.get("compatible_personas"), "compatible_personas", 1, 10)
    if requirements.get("risk_level") not in RISK_LEVELS:
        raise ValueError("risk_level is invalid")
    if requirements.get("resource_cost") not in RESOURCE_COSTS:
        raise ValueError("resource_cost is invalid")

    protocol = value.get("supported_protocol")
    if protocol not in PROTOCOLS:
        raise ValueError("supported_protocol is invalid")
    requested = _strings(value.get("requested_asset_types"), "requested_asset_types", 1, 5)
    if not set(requested) <= ASSET_TYPES:
        raise ValueError("requested asset type is unsupported")
    if "synthetic_rows" in requested and "schema_metadata" not in requested:
        raise ValueError("synthetic_rows requires schema_metadata")

    summary = value.get("existing_synthetic_schema_summary")
    if not isinstance(summary, list) or len(summary) > 20:
        raise ValueError("existing schema summary must contain at most 20 tables")
    seen_tables: set[str] = set()
    for table in summary:
        if not isinstance(table, dict) or set(table) != {"table", "columns"}:
            raise ValueError("existing schema summary table is invalid")
        table_name = _identifier(table.get("table"), "existing table")
        if table_name.lower() in seen_tables:
            raise ValueError("existing schema summary contains duplicate tables")
        seen_tables.add(table_name.lower())
        columns = table.get("columns")
        if not isinstance(columns, list) or not 1 <= len(columns) <= 12:
            raise ValueError("existing schema columns are invalid")
        seen_columns: set[str] = set()
        for column in columns:
            if not isinstance(column, dict) or set(column) != {"name", "type"}:
                raise ValueError("existing schema column is invalid")
            column_name = _identifier(column.get("name"), "existing column")
            if column_name.lower() in seen_columns or column.get("type") not in SQL_TYPES:
                raise ValueError("existing schema column name or type is invalid")
            seen_columns.add(column_name.lower())
    _safe_strings({"persona": persona, "schema_summary": summary})
    result = copy.deepcopy(value)
    result["proposal"] = proposal
    return result


def parse_candidate_json(text: Any) -> dict:
    if not isinstance(text, str) or not text.strip() or len(text) > 32_768:
        raise ValueError("model output must be bounded JSON text")
    if text.lstrip().startswith("```"):
        raise ValueError("markdown-wrapped model output is not accepted")
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("model output is malformed JSON") from exc
    if not isinstance(value, dict) or set(value) != _OUTPUT_FIELDS:
        raise ValueError("model output schema is invalid")
    return validate_candidate_output(value)


def _validate_row_value(value: Any, type_name: str) -> None:
    if value is None:
        return
    if type_name in {"INT", "BIGINT"}:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("integer column contains a non-integer value")
    elif type_name == "BOOLEAN":
        if not isinstance(value, bool):
            raise ValueError("boolean column contains a non-boolean value")
    elif type_name == "DECIMAL":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise ValueError("decimal column contains a nonfinite/non-numeric value")
    elif not isinstance(value, str) or len(value) > 256:
        raise ValueError("text column contains an invalid or oversized value")


def validate_candidate_output(value: dict) -> dict:
    if len(_canonical(value)) > 128_000:
        raise ValueError("candidate output exceeds 128000 bytes")
    description = _text(value.get("description"), "description", 1024)
    tables = value.get("tables")
    if not isinstance(tables, list) or len(tables) > 5:
        raise ValueError("tables must contain at most 5 entries")
    table_index: dict[str, dict] = {}
    table_order: list[str] = []
    for table in tables:
        if not isinstance(table, dict) or set(table) != {
            "name", "columns", "primary_key", "foreign_keys", "indexes", "rows"
        }:
            raise ValueError("table schema is invalid")
        name = _identifier(table.get("name"), "table name")
        if name.lower() in table_index:
            raise ValueError("duplicate table name")
        columns = table.get("columns")
        if not isinstance(columns, list) or not 1 <= len(columns) <= 12:
            raise ValueError("table must contain between 1 and 12 columns")
        column_index: dict[str, dict] = {}
        for column in columns:
            if not isinstance(column, dict) or set(column) != {"name", "type", "nullable"}:
                raise ValueError("column schema is invalid")
            column_name = _identifier(column.get("name"), "column name")
            if column_name.lower() in column_index or column.get("type") not in SQL_TYPES:
                raise ValueError("column name/type is invalid or duplicated")
            if not isinstance(column.get("nullable"), bool):
                raise ValueError("column nullable must be boolean")
            column_index[column_name.lower()] = column
        primary = table.get("primary_key")
        if not isinstance(primary, list) or len(primary) > 4 or any(
            not isinstance(item, str) or item.lower() not in column_index for item in primary
        ) or len({item.lower() for item in primary}) != len(primary):
            raise ValueError("primary key references an invalid column")
        rows = table.get("rows")
        if not isinstance(rows, list) or len(rows) > 20:
            raise ValueError("table rows exceed the limit")
        for row in rows:
            if not isinstance(row, dict) or {key.lower() for key in row} != set(column_index):
                raise ValueError("synthetic row fields must exactly match table columns")
            for key, row_value in row.items():
                column = column_index[key.lower()]
                if row_value is None and column["nullable"] is not True:
                    raise ValueError("non-nullable column contains null")
                _validate_row_value(row_value, column["type"])
        table_index[name.lower()] = {"name": name, "columns": column_index, "table": table}
        table_order.append(name.lower())

    for position, table_name in enumerate(table_order):
        table_entry = table_index[table_name]
        table = table_entry["table"]
        foreign_keys = table.get("foreign_keys")
        if not isinstance(foreign_keys, list) or len(foreign_keys) > 8:
            raise ValueError("foreign keys exceed the limit")
        for foreign_key in foreign_keys:
            if not isinstance(foreign_key, dict) or set(foreign_key) != {
                "columns", "references_table", "references_columns"
            }:
                raise ValueError("foreign key schema is invalid")
            target_name = str(foreign_key.get("references_table") or "").lower()
            if target_name not in table_index or table_order.index(target_name) >= position:
                raise ValueError("foreign key target must be an earlier generated table")
            local = foreign_key.get("columns")
            remote = foreign_key.get("references_columns")
            if (
                not isinstance(local, list) or not isinstance(remote, list) or not local
                or len(local) != len(remote)
                or any(str(item).lower() not in table_entry["columns"] for item in local)
                or any(str(item).lower() not in table_index[target_name]["columns"] for item in remote)
            ):
                raise ValueError("foreign key references an invalid column")
        indexes = table.get("indexes")
        if not isinstance(indexes, list) or len(indexes) > 8:
            raise ValueError("indexes exceed the limit")
        seen_indexes: set[str] = set()
        for index in indexes:
            if not isinstance(index, dict) or set(index) != {"name", "columns"}:
                raise ValueError("index schema is invalid")
            index_name = _identifier(index.get("name"), "index name")
            if index_name.lower() in seen_indexes:
                raise ValueError("duplicate index name")
            columns = index.get("columns")
            if not isinstance(columns, list) or not columns or any(
                str(item).lower() not in table_entry["columns"] for item in columns
            ):
                raise ValueError("index references an invalid column")
            seen_indexes.add(index_name.lower())

    backups = value.get("backup_archives")
    if not isinstance(backups, list) or len(backups) > 10:
        raise ValueError("backup metadata exceeds the limit")
    for backup in backups:
        if not isinstance(backup, dict) or set(backup) != {
            "name", "format", "retention_label", "description"
        }:
            raise ValueError("backup metadata schema is invalid")
        _identifier(backup.get("name"), "backup name")
        if backup.get("format") not in {"logical_dump", "snapshot", "archive_bundle"}:
            raise ValueError("backup format is invalid")
        _identifier(backup.get("retention_label"), "retention label")
        _text(backup.get("description"), "backup description", 512)

    migrations = value.get("migrations")
    if not isinstance(migrations, list) or len(migrations) > 10:
        raise ValueError("migration artifacts exceed the limit")
    for migration in migrations:
        if not isinstance(migration, dict) or set(migration) != {
            "name", "from_version", "to_version", "summary", "affected_tables"
        }:
            raise ValueError("migration artifact schema is invalid")
        _identifier(migration.get("name"), "migration name")
        if not _VERSION.fullmatch(_text(migration.get("from_version"), "from_version", 32)):
            raise ValueError("from_version is invalid")
        if not _VERSION.fullmatch(_text(migration.get("to_version"), "to_version", 32)):
            raise ValueError("to_version is invalid")
        _text(migration.get("summary"), "migration summary", 512)
        _strings(migration.get("affected_tables"), "affected_tables", 0, 10)

    audits = value.get("audit_history")
    if not isinstance(audits, list) or len(audits) > 20:
        raise ValueError("audit history exceeds the limit")
    for position, audit in enumerate(audits, start=1):
        if not isinstance(audit, dict) or set(audit) != {
            "sequence", "event_type", "object_name", "summary"
        }:
            raise ValueError("audit history schema is invalid")
        if audit.get("sequence") != position:
            raise ValueError("audit sequence must be contiguous and deterministic")
        if audit.get("event_type") not in {"created", "updated", "archived", "reviewed"}:
            raise ValueError("audit event type is invalid")
        _identifier(audit.get("object_name"), "audit object name")
        _text(audit.get("summary"), "audit summary", 512)

    _safe_strings(value)
    return copy.deepcopy(value)


def enforce_requested_assets(candidate: dict, requested: list[str]) -> None:
    requirements = {
        "schema_metadata": bool(candidate["tables"]),
        "synthetic_rows": any(table["rows"] for table in candidate["tables"]),
        "backup_archive_metadata": bool(candidate["backup_archives"]),
        "migration_artifact": bool(candidate["migrations"]),
        "audit_history": bool(candidate["audit_history"]),
    }
    fields = {
        "schema_metadata": "tables",
        "synthetic_rows": None,
        "backup_archive_metadata": "backup_archives",
        "migration_artifact": "migrations",
        "audit_history": "audit_history",
    }
    for asset_type, present in requirements.items():
        if asset_type in requested and not present:
            raise ValueError(f"requested {asset_type} is missing")
        field = fields[asset_type]
        if asset_type not in requested and field and candidate[field]:
            raise ValueError(f"unrequested {asset_type} was generated")
    if "synthetic_rows" not in requested and any(table["rows"] for table in candidate["tables"]):
        raise ValueError("unrequested synthetic_rows were generated")


def render_phase17_assets(candidate: dict, protocol: str) -> list[dict]:
    assets: list[dict] = []
    for table in candidate["tables"]:
        definitions = []
        for column in table["columns"]:
            type_name = "VARCHAR(256)" if column["type"] == "VARCHAR" else column["type"]
            definition = f"{column['name']} {type_name}"
            if column["nullable"] is False:
                definition += " NOT NULL"
            definitions.append(definition)
        if table["primary_key"]:
            definitions.append(f"PRIMARY KEY ({', '.join(table['primary_key'])})")
        for foreign_key in table["foreign_keys"]:
            definitions.append(
                f"FOREIGN KEY ({', '.join(foreign_key['columns'])}) REFERENCES "
                f"{foreign_key['references_table']} ({', '.join(foreign_key['references_columns'])})"
            )
        schema_foreign_keys = [
            {
                "columns": item["columns"],
                "references_asset": item["references_table"],
                "references_columns": item["references_columns"],
            }
            for item in table["foreign_keys"]
        ]
        assets.append({
            "asset_id": table["name"],
            "protocol": protocol,
            "object_type": "table",
            "sql": f"CREATE TABLE {table['name']} ({', '.join(definitions)})",
            "schema": {
                "table": table["name"],
                "columns": table["columns"],
                "primary_key": table["primary_key"],
                "foreign_keys": schema_foreign_keys,
                "indexes": table["indexes"],
            },
            "rows": table["rows"],
        })
    return assets
