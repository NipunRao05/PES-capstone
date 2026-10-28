# Pass 5B — Strategy Version Integrity and Executable Action Binding

> Pass 5C progress — 2026-10-28: each approved engine action family now has a
> tested producer-side identity and internal expected/actual comparison. Metadata
> stays on Python response objects; uncovered external/direct principal paths are
> not claimed verified. See ACTION_PROVENANCE_MODEL.md. Historical findings follow.

2026-10-28. **PARTIAL**. Version history and repository digest checking are
IMPLEMENTED / VERIFIED BY TEST. Precise executable provenance remains PARTIAL.

The existing YAML and StrategyRegistry remain authoritative metadata. Definitions
are indexed by (ID, version); `get(id, version)` never falls back. `get(id)` uses
explicit `active_versions`. Multiple versions require an explicit active map.
Legacy single-definition entries infer their sole version. Production remains v1.

Semantic SHA-256 covers canonical JSON of ID, version, action_binding, protocols,
required/forbidden state, activation conditions, personas, schema/trap assets,
risk/resource metadata and commitment preconditions. Lists are sorted and JSON
keys sorted. Description/name/evidence/validation_version, approval and active
pointers are excluded. Governance can disable a definition without changing its
digest. The coarse compatibility implementation field is excluded.

`deception_engine/strategies/registry.lock.json` retains expected ID:version
digests. File loading requires every present definition to match its lock entry;
extra historical entries are retained and accepted. Runtime never writes the lock.
In-memory fixture construction is separate from file integrity validation.
The existing load_with_fallback wrapper still reports degraded mode and uses the
built-in D0 on load failure. Direct load raises an integrity error naming ID/version.
This is repository integrity checking, not tamper-proof security: changing both
definition and lock requires source-control review. Digests do not pin Python code,
schema assets or generator versions. There is no runtime lock-update command.

Bounded action-family map (all v1):

| ID | Approval | Binding | Existing implementation boundary |
| --- | --- | --- | --- |
| D0 | APPROVED | baseline_response | banners, passthrough, safe fallback and default annotations |
| D1 | APPROVED | catalog_response | catalog/information_schema/SHOW handlers |
| D2 | APPROVED | backup_asset_read | managed read/count handlers with backup asset mapping |
| D3 | APPROVED | credential_asset_read | same handlers with credential asset mapping |
| D4 | APPROVED | sensitive_asset_read | same handlers with sensitive asset mapping |
| D5 | REQUIRES_REVIEW | review_only | no approved executable claim |
| D6 | APPROVED | managed_mutation | _handle_mutation |

D7 remains unmapped. Legacy bindings are inferred only for these known IDs;
unknown action names and approved review_only are rejected. Existing rules and
handlers are unchanged. Binding identities are available internally on resolved
Strategy objects and serialized metadata, alongside the computed definition digest.

Architectural limit: `_json_response` resolves the strategy annotation after
response construction; a strategy ID does not uniquely prove which preceding
handler ran. A bounded binding name alone cannot establish executable provenance.
This pass has not added a new dispatcher or changed SQL behavior to force that
relationship. Completing binding validation requires a scoped producer-side action
identity contract across existing response branches before decision tracing.
Preflight integration is deferred; registry file loading validates its adjacent lock.

Tests: new test_strategy_version_integrity.py covers coexistence, exact/active
lookup, invalid pointers, matching/mismatched locks without mutation, editorial
digest stability, unknown binding rejection and D5/D7 preservation. Existing
registry, policy, precondition and commitment suites also pass.

From deception_engine, with existing pass2-tooling on PYTHONPATH and
PYTHONDONTWRITEBYTECODE=1, bundled Python command:

```text
python -m pytest -q -p no:cacheprovider test_strategy_version_integrity.py test_strategy_commitment_preconditions.py test_strategy_registry.py test_policy_guard.py test_world_commitments.py test_world_commitment_lifecycle.py
```

**54 PASS, 3.35s**. No protocol code changes, Go tests, live stack or health checks.
Runtime health NOT VERIFIED. No decision trace, experiment registry, scoring,
learner, shadow mode, adaptive selector, gap detector, candidate generation,
attack graph or automatic promotion. Before Pass 6, complete producer-side binding
verification; then scope decision/application tracing and experiments separately.
