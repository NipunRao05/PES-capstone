"""Fixed Phase 19.1 Ornith runtime and structured-output contract."""

from __future__ import annotations

ORNITH_MODEL = "ornith-1.5:9b"
SEMANTIC_CLIENT_VERSION = "local-llm-semantic-client-v1"
SEMANTIC_SCHEMA_VERSION = "semantic-proposal-output-v1"
SEMANTIC_SEED = 20260827

SEMANTIC_PROPOSAL_JSON_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "proposal_name", "theme", "narrative", "entities", "relationships",
        "clues_traps", "expected_attacker_interests", "rationale",
    ],
    "properties": {
        "proposal_name": {"type": "string", "minLength": 3, "maxLength": 96},
        "theme": {"type": "string", "minLength": 3, "maxLength": 96},
        "narrative": {"type": "string", "minLength": 20, "maxLength": 1200},
        "entities": {
            "type": "array", "minItems": 2, "maxItems": 5,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["name", "role", "description"],
                "properties": {
                    "name": {"type": "string", "minLength": 2, "maxLength": 64},
                    "role": {"type": "string", "minLength": 3, "maxLength": 96},
                    "description": {"type": "string", "minLength": 10, "maxLength": 400},
                },
            },
        },
        "relationships": {
            "type": "array", "minItems": 1, "maxItems": 6,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["source_entity", "target_entity", "relationship", "description"],
                "properties": {
                    "source_entity": {"type": "string", "minLength": 2, "maxLength": 64},
                    "target_entity": {"type": "string", "minLength": 2, "maxLength": 64},
                    "relationship": {"type": "string", "minLength": 3, "maxLength": 96},
                    "description": {"type": "string", "minLength": 10, "maxLength": 400},
                },
            },
        },
        "clues_traps": {
            "type": "array", "minItems": 1, "maxItems": 6,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["name", "kind", "description", "interaction_signal"],
                "properties": {
                    "name": {"type": "string", "minLength": 2, "maxLength": 64},
                    "kind": {
                        "type": "string",
                        "enum": ["metadata_clue", "navigation_clue", "recorded_trap", "consistency_clue"],
                    },
                    "description": {"type": "string", "minLength": 10, "maxLength": 400},
                    "interaction_signal": {"type": "string", "minLength": 3, "maxLength": 160},
                },
            },
        },
        "expected_attacker_interests": {
            "type": "array", "minItems": 1, "maxItems": 6,
            "items": {"type": "string", "minLength": 3, "maxLength": 128},
        },
        "rationale": {"type": "string", "minLength": 20, "maxLength": 800},
    },
}

