"""
schema_loader.py — Loads YAML schema definitions and provides table lookups.

All world definitions in ``schemas/*.yaml`` are loaded at startup.
The active schema for a session is determined by the database name
in the connection's event stream.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

SCHEMAS_DIR = Path(__file__).parent / "schemas"

# Backward-compatible aliases. New worlds should declare aliases in YAML.
LEGACY_DATABASE_TO_SCHEMA = {
    "hr":          "hr",
    "hr_prod":     "hr",
    "hr_production": "hr",
    "finance":     "finance",
    "finance_prod": "finance",
    "finance_production": "finance",
    "crm":         "crm",
    "crm_prod":    "crm",
    "crm_production": "crm",
    # Default fallback
    "testdb":      "hr",
    "production":  "hr",
}

DEFAULT_SCHEMA = "hr"

# PostgreSQL information_schema data_type values derived from the same YAML
# column types that drive row generation.  A column may override this with an
# explicit sql_type when it needs a more precise schema contract.
SQL_TYPE_BY_GENERATOR_TYPE = {
    "pk_int": "integer",
    "fk": "integer",
    "int_range": "integer",
    "float_range": "double precision",
    "money": "numeric",
    "bool": "boolean",
    "past_date": "date",
    "future_date": "date",
    "past_datetime": "timestamp without time zone",
    "uuid": "uuid",
    "json_blob": "jsonb",
}

MYSQL_TYPE_BY_SQL_TYPE = {
    "integer": "int",
    "double precision": "double",
    "numeric": "decimal(12,2)",
    "boolean": "tinyint(1)",
    "date": "date",
    "timestamp without time zone": "datetime",
    "uuid": "char(36)",
    "jsonb": "json",
    "character varying": "varchar(255)",
}

SUPPORTED_GENERATOR_TYPES = frozenset({
    "pk_int", "uuid", "name", "first_name", "last_name", "email", "phone",
    "company", "job_title", "address", "ipv4", "url", "country", "sentence",
    "json_blob", "past_date", "past_datetime", "future_date", "money",
    "credit_card_number", "credit_card_expire", "iban", "routing", "ssn",
    "bcrypt", "password", "api_key", "aws_access_key", "user_agent", "bank",
    "bool", "int_range", "float_range", "choice", "fk",
})

_WORLD_KEYS = {"schema", "description", "settings", "tables", "functions"}
_SETTINGS_KEYS = {"database_name", "database_aliases", "charset"}
_ASSET_KEYS = {
    "description", "exposure_depth", "row_count", "columns", "is_trap",
    "trap_id", "trap_kind", "strategy_id", "mitre_technique_id", "risk_score",
}
_COLUMN_KEYS = {
    "name", "type", "nullable", "sql_type", "numeric_precision", "numeric_scale",
    "domain", "choices", "min", "max", "years_back", "days_back", "days_ahead",
    "decimals", "true_ratio", "ref",
}
_SAFE_TRAP_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_SAFE_TRAP_KIND = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SAFE_TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?")
_SAFE_STRATEGY = re.compile(r"D\d+")


def _safe_identifier(value: str) -> bool:
    return re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", str(value or "").strip().lower()) is not None


class SchemaLoader:
    """
    Loads all YAML schema definitions at startup.
    Provides:
      - get_table(schema, table_name) → table definition dict or None
      - get_tables_at_depth(schema, depth) → list of table names
      - is_trap_table(schema, table_name) → bool
      - schema_for_database(db_name) → schema name string
    """

    def __init__(self, schemas_dir: Path | None = None):
        self._dir = schemas_dir or SCHEMAS_DIR
        # schema_name → {tables: {table_name → table_def}}
        self._schemas: dict[str, dict] = {}
        self._database_to_schema: dict[str, str] = dict(LEGACY_DATABASE_TO_SCHEMA)
        self._database_names: list[str] = []
        self._load_errors: list[str] = []
        self._trap_ids: set[str] = set()
        self._load_all()

    def _load_all(self) -> None:
        for path in sorted(self._dir.glob("*.yaml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    raise ValueError("world root must be a mapping")
                name = str(data.get("schema", path.stem)).strip().lower()
                if not _safe_identifier(name):
                    raise ValueError(f"unsafe schema/world identifier: {name!r}")
                if name in self._schemas:
                    raise ValueError(f"duplicate schema/world identifier: {name!r}")
                self._validate_world(data, name)
                settings = data.get("settings", {}) or {}
                database_name = str(settings.get("database_name") or name).strip().lower()
                aliases = settings.get("database_aliases", []) or []
                if not isinstance(aliases, list):
                    raise ValueError("settings.database_aliases must be a list")
                resolved_aliases: list[str] = []
                for database in [name, database_name, *aliases]:
                    database = str(database).strip().lower()
                    if not _safe_identifier(database):
                        raise ValueError(f"unsafe database alias: {database!r}")
                    existing = self._database_to_schema.get(database)
                    if existing and existing != name:
                        raise ValueError(
                            f"database alias {database!r} already belongs to {existing!r}"
                        )
                    resolved_aliases.append(database)

                world_trap_ids = [
                    str(definition["trap_id"])
                    for assets in (data.get("tables", {}), data.get("functions", {}) or {})
                    for definition in assets.values()
                    if definition.get("is_trap") is True
                ]
                duplicate_trap = next(
                    (
                        trap_id for trap_id in world_trap_ids
                        if trap_id in self._trap_ids or world_trap_ids.count(trap_id) > 1
                    ),
                    "",
                )
                if duplicate_trap:
                    raise ValueError(f"duplicate trap_id: {duplicate_trap!r}")

                # Commit only after the whole world validates.
                self._schemas[name] = data
                self._trap_ids.update(world_trap_ids)
                for database in resolved_aliases:
                    self._database_to_schema[database] = name
                if database_name not in self._database_names:
                    self._database_names.append(database_name)
                table_count = len(data.get("tables", {}))
                function_count = len(data.get("functions", {}) or {})
                log.info("Loaded world '%s': %d tables, %d functions from %s",
                         name, table_count, function_count, path.name)
            except Exception as e:
                self._load_errors.append(f"{path.name}: {type(e).__name__}: {e}")
                log.error("Failed to load schema %s: %s", path, e)

    @property
    def schemas_dir(self) -> Path:
        return self._dir

    @property
    def is_valid(self) -> bool:
        """True only when every discovered world passed validation."""
        return bool(self._schemas) and not self._load_errors

    def get_load_errors(self) -> list[str]:
        """Return bounded operator-facing configuration errors."""
        return list(self._load_errors)

    def schema_for_database(self, db_name: str) -> str:
        """Return schema name for a given database name."""
        if not db_name:
            return DEFAULT_SCHEMA
        db_lower = db_name.lower()
        return self._database_to_schema.get(db_lower, DEFAULT_SCHEMA)

    def get_database_names(self) -> list[str]:
        """Return the canonical attacker-facing database name for every world."""
        return list(self._database_names)

    def get_database_name(self, schema_name: str) -> str:
        """Return one world's canonical attacker-facing database name."""
        world = self.get_world(schema_name)
        settings = world.get("settings", {}) if isinstance(world, dict) else {}
        return str(settings.get("database_name") or schema_name).strip().lower()

    def get_world(self, schema_name: str) -> dict:
        """Return a loaded world definition (read-only by convention)."""
        return self._schemas.get(schema_name, {})

    def get_table(self, schema_name: str, table_name: str) -> dict | None:
        """Return the table definition dict, or None if not found."""
        schema = self._schemas.get(schema_name, {})
        tables = schema.get("tables", {})
        return tables.get(table_name)

    def get_all_tables(self, schema_name: str) -> dict[str, dict]:
        """Return all table definitions for a schema."""
        return self._schemas.get(schema_name, {}).get("tables", {})

    def get_tables_at_depth(
        self, schema_name: str, max_depth: int
    ) -> list[str]:
        """
        Return table names where exposure_depth <= max_depth.
        Used for progressive SHOW TABLES responses.
        """
        tables = self.get_all_tables(schema_name)
        return [
            name for name, defn in tables.items()
            if defn.get("exposure_depth", 1) <= max_depth
        ]

    def is_trap_table(self, schema_name: str, table_name: str) -> bool:
        """Returns True if the table is marked as a honeytoken/trap."""
        table = self.get_table(schema_name, table_name)
        return bool(table and table.get("is_trap", False))

    def get_trap_tables(self, schema_name: str) -> list[str]:
        """Return all trap table names for a schema."""
        tables = self.get_all_tables(schema_name)
        return [n for n, d in tables.items() if d.get("is_trap", False)]

    def get_function(self, schema_name: str, function_name: str) -> dict | None:
        """Return a declarative set-returning function definition."""
        functions = self._schemas.get(schema_name, {}).get("functions", {}) or {}
        return functions.get(str(function_name or "").strip().lower())

    def get_all_functions(self, schema_name: str) -> dict[str, dict]:
        return self._schemas.get(schema_name, {}).get("functions", {}) or {}

    def get_functions_at_depth(self, schema_name: str, max_depth: int) -> list[str]:
        return [
            name for name, definition in self.get_all_functions(schema_name).items()
            if int(definition.get("exposure_depth", 1)) <= max_depth
        ]

    def get_metadata_routines(
        self, schema_name: str, max_depth: int, routine_schema: str = "public",
        routine_catalog: str | None = None,
    ) -> list[dict]:
        return [
            {
                "routine_catalog": routine_catalog or schema_name,
                "routine_schema": routine_schema,
                "routine_name": name,
                "routine_type": "FUNCTION",
                "data_type": "record",
            }
            for name in self.get_functions_at_depth(schema_name, max_depth)
        ]

    @classmethod
    def _validate_world(cls, data: dict[str, Any], world_name: str) -> None:
        """Validate the complete declarative world before it can be served."""
        unknown = set(data) - _WORLD_KEYS
        if unknown:
            raise ValueError(f"unsupported world keys: {', '.join(sorted(unknown))}")
        settings = data.get("settings", {}) or {}
        if not isinstance(settings, dict):
            raise ValueError("settings must be a mapping")
        unknown_settings = set(settings) - _SETTINGS_KEYS
        if unknown_settings:
            raise ValueError(
                f"unsupported settings keys: {', '.join(sorted(unknown_settings))}"
            )
        tables = data.get("tables", {}) or {}
        functions = data.get("functions", {}) or {}
        if not isinstance(tables, dict) or not tables:
            raise ValueError("tables must be a non-empty mapping")
        if not isinstance(functions, dict):
            raise ValueError("functions must be a mapping")
        overlap = set(tables) & set(functions)
        if overlap:
            raise ValueError(
                f"table/function names overlap: {', '.join(sorted(overlap))}"
            )
        cls._validate_assets("table", tables)
        cls._validate_assets("function", functions)
        cls._validate_foreign_keys(world_name, tables, functions)

    @classmethod
    def _validate_assets(cls, asset_kind: str, assets: dict[str, Any]) -> None:
        """Validate generated tables/functions; executable SQL is never accepted."""
        for name, definition in assets.items():
            canonical_name = str(name or "").strip().lower()
            if (
                str(name) != canonical_name
                or not _safe_identifier(canonical_name)
                or not isinstance(definition, dict)
            ):
                raise ValueError(f"invalid {asset_kind} definition: {name!r}")
            unknown = set(definition) - _ASSET_KEYS
            if unknown:
                raise ValueError(
                    f"unsupported keys in {asset_kind} {name!r}: {', '.join(sorted(unknown))}"
                )
            try:
                depth = int(definition.get("exposure_depth", 1))
                row_count = int(definition.get("row_count", 1))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"invalid depth/row_count for {asset_kind} {name!r}") from exc
            if depth not in {1, 2, 3} or not 0 <= row_count <= 100_000:
                raise ValueError(f"invalid depth/row_count for {asset_kind} {name!r}")
            if "is_trap" in definition and not isinstance(definition["is_trap"], bool):
                raise ValueError(f"{asset_kind} {name!r}.is_trap must be boolean")
            columns = definition.get("columns", [])
            cls._validate_columns(asset_kind, str(name), columns)
            if definition.get("is_trap") is True:
                cls._validate_trap(asset_kind, str(name), definition)
            elif any(key in definition for key in (
                "trap_id", "trap_kind", "mitre_technique_id", "risk_score"
            )):
                raise ValueError(
                    f"{asset_kind} {name!r} has trap metadata but is_trap is not true"
                )
            strategy_id = str(definition.get("strategy_id") or "").strip().upper()
            if strategy_id and not _SAFE_STRATEGY.fullmatch(strategy_id):
                raise ValueError(f"{asset_kind} {name!r} has invalid strategy_id")

    @staticmethod
    def _validate_columns(asset_kind: str, asset_name: str, columns: Any) -> None:
        if not isinstance(columns, list) or not columns or len(columns) > 128:
            raise ValueError(f"{asset_kind} {asset_name!r} requires 1..128 generated columns")
        names: set[str] = set()
        for column in columns:
            if not isinstance(column, dict):
                raise ValueError(f"{asset_kind} {asset_name!r} has a non-mapping column")
            unknown = set(column) - _COLUMN_KEYS
            if unknown:
                raise ValueError(
                    f"{asset_kind} {asset_name!r} column has unsupported keys: "
                    f"{', '.join(sorted(unknown))}"
                )
            name = str(column.get("name") or "").strip().lower()
            generator_type = str(column.get("type") or "sentence").strip().lower()
            if str(column.get("name") or "") != name or not _safe_identifier(name) or name in names:
                raise ValueError(f"{asset_kind} {asset_name!r} has invalid/duplicate column {name!r}")
            names.add(name)
            if generator_type not in SUPPORTED_GENERATOR_TYPES:
                raise ValueError(
                    f"{asset_kind} {asset_name!r}.{name} uses unsupported generator {generator_type!r}"
                )
            if str(column.get("type") or "sentence") != generator_type:
                raise ValueError(
                    f"{asset_kind} {asset_name!r}.{name} generator names must be lowercase"
                )
            if "nullable" in column and not isinstance(column["nullable"], bool):
                raise ValueError(f"{asset_kind} {asset_name!r}.{name}.nullable must be boolean")
            if generator_type == "choice":
                choices = column.get("choices")
                if not isinstance(choices, list) or not choices or len(choices) > 256:
                    raise ValueError(f"{asset_kind} {asset_name!r}.{name} needs 1..256 choices")
                if any(isinstance(item, (dict, list)) or item is None for item in choices):
                    raise ValueError(f"{asset_kind} {asset_name!r}.{name} has invalid choices")
            if generator_type in {"int_range", "float_range", "money"}:
                try:
                    if float(column.get("min", 0)) > float(column.get("max", 100)):
                        raise ValueError("min exceeds max")
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{asset_kind} {asset_name!r}.{name} has invalid range") from exc
            if generator_type == "bool":
                try:
                    ratio = float(column.get("true_ratio", 0.5))
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"{asset_kind} {asset_name!r}.{name} has invalid true_ratio") from exc
                if not 0 <= ratio <= 1:
                    raise ValueError(f"{asset_kind} {asset_name!r}.{name}.true_ratio must be in [0, 1]")
            for bound in ("years_back", "days_back", "days_ahead", "decimals"):
                if bound in column:
                    try:
                        value = int(column[bound])
                    except (TypeError, ValueError) as exc:
                        raise ValueError(f"{asset_kind} {asset_name!r}.{name}.{bound} is invalid") from exc
                    if value < 0 or value > 10_000:
                        raise ValueError(f"{asset_kind} {asset_name!r}.{name}.{bound} is out of bounds")
            if "sql_type" in column and not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9 ]{0,40}(?:\(\d+(?:,\d+)?\))?", str(column["sql_type"])
            ):
                raise ValueError(f"{asset_kind} {asset_name!r}.{name}.sql_type is unsafe")

    @staticmethod
    def _validate_trap(asset_kind: str, asset_name: str, definition: dict[str, Any]) -> None:
        trap_id = str(definition.get("trap_id") or "")
        trap_kind = str(definition.get("trap_kind") or "")
        strategy_id = str(definition.get("strategy_id") or "").strip().upper()
        technique = str(definition.get("mitre_technique_id") or "")
        try:
            risk_score = float(definition.get("risk_score", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"trap {asset_kind} {asset_name!r} has invalid risk_score") from exc
        if not _SAFE_TRAP_ID.fullmatch(trap_id):
            raise ValueError(f"trap {asset_kind} {asset_name!r} requires a safe trap_id")
        if not _SAFE_TRAP_KIND.fullmatch(trap_kind):
            raise ValueError(f"trap {asset_kind} {asset_name!r} requires a safe trap_kind")
        if not _SAFE_STRATEGY.fullmatch(strategy_id):
            raise ValueError(f"trap {asset_kind} {asset_name!r} requires a strategy_id")
        if not _SAFE_TECHNIQUE.fullmatch(technique):
            raise ValueError(f"trap {asset_kind} {asset_name!r} requires a MITRE technique ID")
        if not 0 < risk_score <= 25:
            raise ValueError(f"trap {asset_kind} {asset_name!r} risk_score must be in (0, 25]")

    @staticmethod
    def _validate_foreign_keys(
        world_name: str, tables: dict[str, Any], functions: dict[str, Any]
    ) -> None:
        for asset_name, definition in {**tables, **functions}.items():
            for column in definition.get("columns", []):
                if column.get("type") != "fk":
                    continue
                ref = str(column.get("ref") or "").strip().lower()
                match = re.fullmatch(r"([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)", ref)
                if not match:
                    raise ValueError(f"{world_name}.{asset_name}.{column['name']} has invalid FK ref")
                target_table, target_column = match.groups()
                target = tables.get(target_table)
                target_columns = {
                    str(item.get("name") or "").lower(): str(item.get("type") or "").lower()
                    for item in (target or {}).get("columns", [])
                }
                if target_table not in tables or target_columns.get(target_column) != "pk_int":
                    raise ValueError(
                        f"{world_name}.{asset_name}.{column['name']} references missing/non-integer PK {ref}"
                    )

    def get_row_count(self, schema_name: str, table_name: str) -> int:
        """Return the configured row_count for a table."""
        table = self.get_table(schema_name, table_name)
        return table.get("row_count", 100) if table else 0

    def get_columns(self, schema_name: str, table_name: str) -> list[dict]:
        """Return the column definitions for a table."""
        table = self.get_table(schema_name, table_name)
        return table.get("columns", []) if table else []

    def get_schema_names(self) -> list[str]:
        """Return all loaded schema names."""
        return list(self._schemas.keys())

    def get_metadata_tables(
        self, schema_name: str, max_depth: int, table_schema: str = "public",
        table_catalog: str | None = None,
    ) -> list[dict]:
        """Render information_schema.tables rows from the canonical YAML."""
        return [
            {
                "table_catalog": table_catalog or schema_name,
                "table_schema": table_schema,
                "table_name": table_name,
                "table_type": "BASE TABLE",
            }
            for table_name in self.get_tables_at_depth(schema_name, max_depth)
        ]

    def get_metadata_columns(
        self, schema_name: str, max_depth: int, table_schema: str = "public",
        table_catalog: str | None = None,
    ) -> list[dict]:
        """Render information_schema.columns rows from the canonical YAML."""
        rows: list[dict] = []
        for table_name in self.get_tables_at_depth(schema_name, max_depth):
            for ordinal, column in enumerate(self.get_columns(schema_name, table_name), start=1):
                generator_type = column.get("type", "sentence")
                row = {
                    "table_catalog": table_catalog or schema_name,
                    "table_schema": table_schema,
                    "table_name": table_name,
                    "column_name": column["name"],
                    "ordinal_position": ordinal,
                    "column_default": None,
                    "is_nullable": "YES" if column.get("nullable", False) else "NO",
                    "data_type": column.get(
                        "sql_type",
                        SQL_TYPE_BY_GENERATOR_TYPE.get(generator_type, "character varying"),
                    ),
                }
                if "numeric_precision" in column:
                    row["numeric_precision"] = int(column["numeric_precision"])
                if "numeric_scale" in column:
                    row["numeric_scale"] = int(column["numeric_scale"])
                rows.append(row)
        return rows

    def get_mysql_columns(self, schema_name: str, table_name: str) -> list[dict]:
        """Render the bounded DESCRIBE/SHOW COLUMNS surface from YAML."""
        rows: list[dict] = []
        for column in self.get_columns(schema_name, table_name):
            sql_type = column.get(
                "sql_type",
                SQL_TYPE_BY_GENERATOR_TYPE.get(column.get("type", "sentence"), "character varying"),
            )
            mysql_type = MYSQL_TYPE_BY_SQL_TYPE.get(sql_type, "varchar(255)")
            if sql_type == "numeric":
                precision = int(column.get("numeric_precision", 12))
                scale = int(column.get("numeric_scale", 2))
                mysql_type = f"decimal({precision},{scale})"
            rows.append({
                "Field": column["name"],
                "Type": mysql_type,
                "Null": "YES" if column.get("nullable", False) else "NO",
                "Key": "PRI" if column.get("type") == "pk_int" else "",
                "Default": None,
                "Extra": "",
            })
        return rows
