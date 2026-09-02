"""
schema_loader.py — Loads YAML schema definitions and provides table lookups.

All three industry schemas (HR, Finance, CRM) are loaded at startup.
The active schema for a session is determined by the database name
in the connection's event stream.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

SCHEMAS_DIR = Path(__file__).parent / "schemas"

# Map database names (or prefixes) → schema file
DATABASE_TO_SCHEMA = {
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
        self._load_all()

    def _load_all(self) -> None:
        for path in sorted(self._dir.glob("*.yaml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                name = data.get("schema", path.stem)
                self._schemas[name] = data
                table_count = len(data.get("tables", {}))
                log.info("Loaded schema '%s': %d tables from %s",
                         name, table_count, path.name)
            except Exception as e:
                log.error("Failed to load schema %s: %s", path, e)

    def schema_for_database(self, db_name: str) -> str:
        """Return schema name for a given database name."""
        if not db_name:
            return DEFAULT_SCHEMA
        db_lower = db_name.lower()
        return DATABASE_TO_SCHEMA.get(db_lower, DEFAULT_SCHEMA)

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
