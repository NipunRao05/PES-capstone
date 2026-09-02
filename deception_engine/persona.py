"""Canonical attacker-facing database personas.

The physical engines remain protocol authorities for handshakes.  These values
match the pinned Compose engine versions and are reused by every synthesized
identity query so SQL-level reconnaissance cannot observe conflicting personas.
"""

from __future__ import annotations

import os

MYSQL_VERSION = os.environ.get("DECEPTION_MYSQL_VERSION", "8.0.45")
MYSQL_VERSION_COMMENT = os.environ.get(
    "DECEPTION_MYSQL_VERSION_COMMENT", "MySQL Community Server - GPL"
)
POSTGRES_SERVER_VERSION = os.environ.get("DECEPTION_POSTGRES_SERVER_VERSION", "16.13")
POSTGRES_VERSION = os.environ.get(
    "DECEPTION_POSTGRES_VERSION",
    f"PostgreSQL {POSTGRES_SERVER_VERSION} on x86_64-pc-linux-gnu, compiled by gcc, 64-bit",
)
DEFAULT_DATABASE = os.environ.get("DECEPTION_DATABASE", "testdb")
DEFAULT_SCHEMA = os.environ.get("DECEPTION_SCHEMA", "public")

