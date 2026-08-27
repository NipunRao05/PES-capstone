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

