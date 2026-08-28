# Phase 19 — Offline Decoy Generation Agent

This package turns an intact Phase 15 proposal and Phase 16
`APPROVED_FOR_VALIDATION` review into an untrusted, bounded candidate. It uses
the private Phase 18 local-model client, accepts strict JSON only, permits one
structural repair, renders only deterministic `CREATE TABLE` candidate SQL, and
passes the result to the existing Phase 17 validator without executing it.

It has no service endpoint and no authority to mutate the registry, policy,
session state, database state, containers, or deployment configuration.

Focused validation:

    python -m unittest -v decoy_generation_agent.test_decoy_generation

## Phase 19.1 semantic proposal path

`semantic-proposal-v1` is a separate metadata-only path for the bounded Ornith
prototype. It preserves `decoy-generation-agent-v1` and never rewrites the Qwen
Phase 19 result. The model proposes only a theme, narrative, semantic entities,
relationships, clues/traps, expected attacker interests, and rationale.
Deterministic code owns IDs, normalization, provenance, validation state, and the
metadata-only Phase 17 handoff.

The runtime request sets `think: false` and an exact JSON Schema in Ollama's
`format` field. Separate reasoning is discarded, reasoning tags in final content
are rejected, and accepted JSON is validated again for schema, semantics, safety,
Phase 15/16 linkage, and Phase 17 compatibility. Candidates remain
`NONDEPLOYABLE` and `REGISTRY_UNAPPROVED`.

Focused validation:

    python -m unittest -v local_llm.test_semantic_client decoy_generation_agent.test_semantic_proposal

The fixed ten-case live benchmark is orchestrated by:

    .\scripts\phase19_1_live_benchmark.ps1 -OutputPath PHASE_19_1_BENCHMARK.json
