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
