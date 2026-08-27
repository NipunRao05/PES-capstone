"""Versioned constants for the bounded Phase 19 contracts."""

GENERATOR_VERSION = "decoy-generation-agent-v1"
REQUEST_VERSION = "decoy-generation-request-v1"
OUTPUT_SCHEMA_VERSION = "decoy-candidate-output-v1"
PROMPT_TEMPLATE_VERSION = "decoy-prompt-v1"
GENERATION_SETTINGS = {"max_tokens": 512, "temperature": 0.2}

ASSET_TYPES = {
    "schema_metadata",
    "synthetic_rows",
    "backup_archive_metadata",
    "migration_artifact",
    "audit_history",
}
PROTOCOLS = {"mysql", "postgres"}
SQL_TYPES = {"INT", "BIGINT", "VARCHAR", "TEXT", "BOOLEAN", "DECIMAL"}
RISK_LEVELS = {"low", "medium", "high", "critical"}
RESOURCE_COSTS = {"low", "medium", "high"}

AUTHORITY = {
    "deployable": False,
    "registry_approved": False,
    "strategy_activation": False,
    "registry_mutation": False,
    "policy_mutation": False,
    "database_execution": False,
    "requires_phase_17_validation": True,
}
