"""
phase_classifier.py
-------------------
Maps normalised SQL fingerprints to MITRE-aligned attack phases.

Phases (in order of attack progression):
  recon            — system metadata probes (@@version, @@hostname)
  enumeration      — schema/table/column discovery
  privilege_discovery — user, role, permission queries
  data_discovery   — broad table scans, COUNT then SELECT patterns
  exploitation     — file read/write, SLEEP probes, UDF abuse
  exfiltration     — large SELECT ... LIMIT, INTO OUTFILE

Returns None for normal application queries that don't match any phase.
"""

import re

# ---------------------------------------------------------------------------
# Rule sets — each is a list of (pattern, phase) tuples.
# Patterns are matched against the lowercased, stripped fingerprint.
# First match wins.
# ---------------------------------------------------------------------------

_EXACT = [
    # recon — system variable probes
    ("select @@version",                    "recon"),
    ("select @@version_comment",            "recon"),
    ("select @@hostname",                   "recon"),
    ("select @@global.version",             "recon"),
    ("select @@datadir",                    "recon"),
    ("select @@basedir",                    "recon"),
    ("select version()",                    "recon"),

    # enumeration — schema discovery
    ("show databases",                      "enumeration"),
    ("show schemas",                        "enumeration"),
    ("show tables",                         "enumeration"),
    ("show columns",                        "enumeration"),
    ("show full tables",                    "enumeration"),
    ("show full columns",                   "enumeration"),
    ("select * from information_schema.schemata",       "enumeration"),
    ("select * from information_schema.tables",         "enumeration"),
    ("select * from information_schema.columns",        "enumeration"),
    ("select * from information_schema.tables limit ?", "enumeration"),
    ("select * from information_schema.columns limit ?","enumeration"),
    ("select * from information_schema.schemata;",      "enumeration"),
    ("select table_name from information_schema.tables","enumeration"),

    # privilege_discovery
    ("select user()",                           "privilege_discovery"),
    ("select current_user()",                   "privilege_discovery"),
    ("select current_user",                     "privilege_discovery"),
    ("select * from mysql.user",                "privilege_discovery"),
    ("select * from information_schema.user_privileges",  "privilege_discovery"),
    ("select * from information_schema.schema_privileges","privilege_discovery"),
    ("show grants",                             "privilege_discovery"),
    ("select @@secure_file_priv",               "privilege_discovery"),

    # exploitation
    ("select sleep(?)",                     "exploitation"),
    ("select benchmark(?,?)",               "exploitation"),
    ("select load_file(?)",                 "exploitation"),
]

_PREFIX = [
    ("select @@",       "recon"),
    ("show ",           "enumeration"),
    ("select * from information_schema.", "enumeration"),
    ("select * from mysql.", "privilege_discovery"),
    ("select load_file", "exploitation"),
]

_CONTAINS = [
    ("into outfile",    "exfiltration"),
    ("into dumpfile",   "exfiltration"),
    ("load_file(",      "exploitation"),
    ("sleep(",          "exploitation"),
    ("benchmark(",      "exploitation"),
    ("information_schema.user_privileges",  "privilege_discovery"),
    ("information_schema.schema_privileges","privilege_discovery"),
    ("information_schema.",                 "enumeration"),
]


def classify_phase(fingerprint: str) -> str | None:
    """
    Returns the attack phase string for a given query fingerprint,
    or None if the query is a normal application query.
    """
    if not fingerprint:
        return None

    fp = fingerprint.lower().strip().rstrip(";").strip()

    # 1. Exact matches first (fastest, most precise)
    if fp in {e[0] for e in _EXACT}:
        for pattern, phase in _EXACT:
            if fp == pattern:
                return phase

    # 2. Prefix matches
    for prefix, phase in _PREFIX:
        if fp.startswith(prefix):
            return phase

    # 3. Substring matches (catch parameterised variants)
    for fragment, phase in _CONTAINS:
        if fragment in fp:
            return phase

    return None


def is_recon_probe(fingerprint: str) -> bool:
    """Returns True if this fingerprint is a system variable probe (@@...)."""
    if not fingerprint:
        return False
    fp = fingerprint.lower().strip()
    return fp.startswith("select @@") or fp.startswith("show ")