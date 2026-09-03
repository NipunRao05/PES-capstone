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
                self._validate_functions(data.get("functions", {}))
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

                # Commit only after the whole world validates.
                self._schemas[name] = data
                for database in resolved_aliases:
                    self._database_to_schema[database] = name
                if database_name not in self._database_names:
                    self._database_names.append(database_name)
                table_count = len(data.get("tables", {}))
                function_count = len(data.get("functions", {}) or {})
                log.info("Loaded world '%s': %d tables, %d functions from %s",
                         name, table_count, function_count, path.name)
            except Exception as e:
                log.error("Failed to load schema %s: %s", path, e)

    def schema_for_database(self, db_name: str) -> str:
        """Return schema name for a given database name."""
        if not db_name:
            return DEFAULT_SCHEMA
        db_lower = db_name.lower()
        return self._database_to_schema.get(db_lower, DEFAULT_SCHEMA)

    def get_database_names(self) -> list[str]:
        """Return the canonical attacker-facing database name for every world."""
        return list(self._database_names)

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

    @staticmethod
    def _validate_functions(functions: object) -> None:
        """Fail closed on the small declarative function-trap contract.

        Functions never contain executable SQL or literal token values. They
        only describe rows generated by the existing deterministic faker.
        """
        if functions in (None, {}):
            return
        if not isinstance(functions, dict):
            raise ValueError("functions must be a mapping")
        for name, definition in functions.items():
            if not _safe_identifier(str(name)) or not isinstance(definition, dict):
                raise ValueError(f"invalid function definition: {name!r}")
            if set(definition) - {
                "description", "exposure_depth", "row_count", "columns",
                "is_trap", "trap_id", "trap_kind", "strategy_id",
                "mitre_technique_id", "risk_score",
            }:
                raise ValueError(f"unsupported keys in function {name!r}")
            depth = int(definition.get("exposure_depth", 1))
            row_count = int(definition.get("row_count", 1))
            if depth not in {1, 2, 3} or not 0 <= row_count <= 100_000:
                raise ValueError(f"invalid depth/row_count for function {name!r}")
            columns = definition.get("columns", [])
            if not isinstance(columns, list) or not columns or len(columns) > 128:
                raise ValueError(f"function {name!r} requires 1..128 generated columns")
            if any(not isinstance(c, dict) or not _safe_identifier(str(c.get("name", ""))) for c in columns):
                raise ValueError(f"function {name!r} has invalid columns")
            if definition.get("is_trap") is True:
                trap_id = str(definition.get("trap_id") or "")
                strategy_id = str(definition.get("strategy_id") or "")
                if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", trap_id):
                    raise ValueError(f"trap function {name!r} requires a safe trap_id")
                if strategy_id not in {"D2", "D3", "D4"}:
                    raise ValueError(
                        f"trap function {name!r} must use approved MVP strategy D2, D3, or D4"
                    )
                technique = str(definition.get("mitre_technique_id") or "")
                risk_score = float(definition.get("risk_score", 0))
                if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                    raise ValueError(f"trap function {name!r} requires a MITRE technique ID")
                if not 0 < risk_score <= 25:
                    raise ValueError(f"trap function {name!r} risk_score must be in (0, 25]")

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
